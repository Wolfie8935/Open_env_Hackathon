"""
Security Scanner Environment
The main environment class implementing the OpenEnv contract.
"""

from fastapi import HTTPException

from environment.models import (
    Action,
    ActionType,
    Finding,
    Observation,
    ReportVulnerabilityAction,
    StepResult,
)
from environment.reward import (
    compute_episode_score,
    compute_step_reward,
    compute_triage_score,
    compute_severity_coverage,
)
from environment.state_manager import StateManager
from environment.config import ENABLE_EVIDENCE_MODE, ENABLE_PRECISION_SCORING

from environment.security_analysis import (
    build_dependency_graph,
    run_static_analysis,
    analyze_dataflows,
    evaluate_exploitability,
    detect_attack_chains,
)

from environment.chain_objective import (
    get_chain_objective,
    format_chain_objective_feedback,
)

DUPLICATE_PENALTY = -0.05

class SecurityScannerEnv:
    """OpenEnv-compatible security vulnerability scanner environment."""

    def __init__(self):
        self.state_manager = StateManager()
        self.active_task = None
        self._initialized = False
        self._dependency_graph = {}
        self._static_results = {}
        self._dataflow_results = {}
        self._exploitability_results = {}
        self._attack_chains = []

    def reset(self, task_id: int) -> Observation:
        task = self._load_task(task_id)
        self.active_task = task
        self.state_manager.initialize(task)

        try:
            self._dependency_graph = build_dependency_graph(task.files)
            self._static_results = run_static_analysis(task.files)
            self._dataflow_results = analyze_dataflows(task.files)
            self._exploitability_results = evaluate_exploitability(
                self._static_results, self._dataflow_results,
            )
            self._attack_chains = detect_attack_chains(
                self._dependency_graph, self._exploitability_results,
            )
        except Exception:
            self._dependency_graph = {}
            self._static_results = {}
            self._dataflow_results = {}
            self._exploitability_results = {}
            self._attack_chains = []

        if task_id == 3:
            for filename in list(task.files.keys()):
                self.state_manager.reveal_file(filename)

        chain_objective = get_chain_objective(task_id)
        self.state_manager.chain_objective = chain_objective
        chain_objective_feedback = format_chain_objective_feedback(chain_objective)

        triage_mode = getattr(task, "triage_mode", False)
        triage_max_steps = getattr(task, "triage_max_steps", task.max_steps)

        self._initialized = True

        base_feedback = (
            f"Episode started for Task {task_id}: {task.name}. "
            f"Analyze the code and report vulnerabilities. "
            f"Files visible: {sorted(self.state_manager.visible_files)}. "
            f"Hidden files: {self.state_manager.get_available_files()}"
        )

        if triage_mode:
            base_feedback += (
                f" | TRIAGE MODE: report Critical then High then Medium. "
                f"Efficient budget: {triage_max_steps} steps."
            )

        return Observation(
            files=self.state_manager.get_visible_file_contents(),
            current_findings=[],
            step_number=0,
            task_id=task_id,
            feedback=base_feedback + chain_objective_feedback,
            remaining_steps=task.max_steps,
            chain_objective=chain_objective,
            chain_progress=[],
            chain_complete=False,
            chain_ordered=True,
            triage_mode=triage_mode,
            triage_score=0.0,
            severity_coverage={},
            priority_budget=triage_max_steps,
            live_chain_status=self.state_manager.get_live_chain_status(),
        )

    def step(self, action: Action) -> StepResult:
        if not self._initialized:
            raise HTTPException(status_code=409, detail="Call /reset first")

        if self.state_manager.is_complete:
            return self._terminal_result("Episode already complete.")

        reward = 0.0
        feedback = ""
        breakdown = {}

        if action.action_type == ActionType.REPORT_VULNERABILITY:
            reward, feedback, breakdown = self._handle_report(action.payload)
        elif action.action_type == ActionType.REQUEST_FILE:
            feedback = self._handle_request_file(action.payload)
        elif action.action_type == ActionType.MARK_COMPLETE:
            feedback, episode_score = self._handle_mark_complete()
            breakdown["episode_score"] = episode_score
        elif action.action_type == ActionType.ADD_NOTE:
            feedback = self._handle_add_note(action.payload)

        self.state_manager.cumulative_reward += reward
        self.state_manager.increment_step()

        triage_mode = self.state_manager.triage_mode
        triage_score = self.state_manager.triage_score_cache if triage_mode else 0.0
        severity_coverage = self.state_manager.severity_coverage_cache or {}

        live_chain_status = self.state_manager.get_live_chain_status()

        observation = Observation(
            files=self.state_manager.get_visible_file_contents(),
            current_findings=self.state_manager.findings,
            step_number=self.state_manager.step_number,
            task_id=self.active_task.task_id,
            feedback=feedback,
            remaining_steps=max(
                0, self.active_task.max_steps - self.state_manager.step_number
            ),
            active_insights=self.state_manager.active_insights,
            suspicious_files=self.state_manager.suspicious_files,
            chain_objective=self.state_manager.chain_objective,
            chain_progress=self.state_manager.chain_steps_found,
            chain_complete=self.state_manager.chain_complete,
            chain_ordered=self.state_manager.chain_ordered,
            triage_mode=triage_mode,
            triage_score=triage_score,
            severity_coverage=severity_coverage,
            priority_budget=max(
                0,
                self.state_manager.triage_max_steps - self.state_manager.step_number
            ),
            live_chain_status=live_chain_status,
        )

        episode_score = self.state_manager.compute_episode_score_cached(
            chain_bonus=0.0,
            use_precision_scoring=ENABLE_PRECISION_SCORING,
            current_step=self.state_manager.step_number,
            max_steps=self.active_task.max_steps,
        )

        clamped_reward = max(-0.5, min(0.6, reward))

        return StepResult(
            observation=observation,
            reward=clamped_reward,
            done=self.state_manager.is_complete,
            info={
                "episode_score": episode_score,
                "step_reward_breakdown": breakdown,
                "grader_feedback": feedback,
                "cumulative_reward": self.state_manager.cumulative_reward,
                "findings_count": len(self.state_manager.findings),
                "ground_truth_count": len(self.active_task.ground_truth),
                "triage_score": triage_score,
                "severity_coverage": severity_coverage,
                "live_chain_status": live_chain_status,
                "chain_progress": self.state_manager.chain_steps_found,
                "chain_complete": self.state_manager.chain_complete,
            },
        )

    def state(self) -> dict:
        if not self._initialized:
            raise HTTPException(
                status_code=409, detail="No active episode. Call /reset first"
            )

        state = self.state_manager.to_state_dict()

        state["findings"] = [
            {
                "file": f.file,
                "line_number": f.line_number,
                "vulnerability_type": f.vulnerability_type,
                "severity": f.severity,
            }
            for f in self.state_manager.findings
        ]

        state["ground_truth"] = [
            {
                "file": gt.get("file"),
                "line": gt.get("line"),
                "type": gt.get("vulnerability_type") or gt.get("type"),
            }
            for gt in self.active_task.ground_truth
        ]

        state["security_analysis"] = self.get_security_analysis_summary()

        return state

    def get_security_analysis_summary(self) -> dict:
        return {
            "files_analyzed": len(self.active_task.files) if self.active_task else 0,
            "dependency_graph": self._dependency_graph,
            "static_analysis": self._static_results,
            "dataflow_analysis": self._dataflow_results,
            "exploitability_analysis": self._exploitability_results,
            "attack_chains": self._attack_chains,
            "summary": {
                "dependency_edges": sum(len(v) for v in self._dependency_graph.values()),
                "static_patterns_detected": sum(len(v) for v in self._static_results.values()),
                "dataflows_detected": sum(len(v) for v in self._dataflow_results.values()),
                "high_risk_flows": sum(
                    1 for flows in self._exploitability_results.values()
                    for f in flows
                    if isinstance(f, dict) and f.get("risk_score", 0) >= 0.7
                ),
                "attack_chains_detected": len(self._attack_chains),
            }
        }

    def _handle_report(self, payload: dict):
        if ENABLE_EVIDENCE_MODE:
            report = ReportVulnerabilityAction(**payload)
        else:
            report = ReportVulnerabilityAction.model_construct(**payload)

        finding = Finding(
            file=report.file,
            line_number=report.line_number,
            vulnerability_type=report.vulnerability_type,
            severity=report.severity,
            description=report.description,
            suggested_fix=report.suggested_fix,
            function=report.function,
            data_flow_source=report.data_flow_source,
            sink=report.sink,
            exploitability_reason=report.exploitability_reason,
        )

        if ENABLE_EVIDENCE_MODE:
            evidence_fields = [
                finding.function, finding.data_flow_source,
                finding.sink, finding.exploitability_reason,
            ]
            if any(v is None or not str(v).strip() for v in evidence_fields):
                raise ValueError(
                    "Evidence mode requires function, data_flow_source, sink, and exploitability_reason"
                )

        reward, breakdown = compute_step_reward(
            finding,
            self.active_task.ground_truth,
            self.active_task.task_id,
            self.state_manager.findings,
        )

        is_duplicate = any(
            f.file == finding.file and f.vulnerability_type == finding.vulnerability_type
            for f in self.state_manager.findings
        )
        if is_duplicate and reward == 0.0:
            reward = DUPLICATE_PENALTY
            breakdown["duplicate_penalty"] = DUPLICATE_PENALTY
            feedback = (
                f"DUPLICATE — already reported {finding.vulnerability_type} in "
                f"{finding.file}. Penalty: {DUPLICATE_PENALTY}. Do not repeat findings."
            )
            return reward, feedback, breakdown

        self.state_manager.add_finding(finding)

        if reward > 0:
            feedback = f"Finding recorded: {finding.vulnerability_type}"

            from environment.reward import _types_match
            for gt in self.active_task.ground_truth:
                if _types_match(finding.vulnerability_type, gt["type"]) and finding.file == gt["file"]:
                    insight = self.state_manager.process_trigger(finding.file, gt["type"])
                    if insight:
                        feedback = f"{feedback} | INSIGHT: {insight}"
                    break

            # Chain Step Processing (live bonus + chain status update)
            chain_live_bonus, chain_feedback = self.state_manager.process_chain_step(
                finding.file, finding.vulnerability_type
            )
            if chain_live_bonus != 0.0:
                reward += chain_live_bonus
                breakdown["chain_live_bonus"] = chain_live_bonus
            if chain_feedback:
                feedback = f"{feedback} | {chain_feedback}"

        elif reward < 0:
            feedback = f"False positive: {finding.vulnerability_type}"
        else:
            feedback = f"Finding noted (partial match): {finding.vulnerability_type}"

        return reward, feedback, breakdown

    def _handle_request_file(self, payload):
        filename = payload.get("filename", "")

        if self.state_manager.reveal_file(filename):
            remaining = self.state_manager.get_available_files()
            return (
                f"File '{filename}' is now visible. "
                f"Remaining hidden files: {remaining if remaining else 'none'}"
            )
        elif filename in self.state_manager.visible_files:
            return f"File '{filename}' is already visible."
        else:
            all_files = sorted(self.active_task.files.keys())
            return f"File '{filename}' not found. Available files: {all_files}"

    def _handle_mark_complete(self):
        self.state_manager.is_complete = True
        attack_chain_bonus, chains = self.state_manager.compute_chain_bonuses()
        self.state_manager.chains_completed = chains

        # Chain objective complete+ordered bonus (live bonuses already applied)
        chain_objective_bonus = self.state_manager.get_chain_objective_bonus_for_mark_complete()
        total_chain_bonus = attack_chain_bonus + chain_objective_bonus

        episode_score = self.state_manager.compute_episode_score_cached(
            chain_bonus=total_chain_bonus,
            use_precision_scoring=ENABLE_PRECISION_SCORING,
            current_step=self.state_manager.step_number,
            max_steps=self.active_task.max_steps,
        )

        final_triage_score = (
            self.state_manager.triage_score_cache
            if self.state_manager.triage_mode
            else 0.0
        )

        feedback = f"Episode complete. Score: {episode_score:.3f}"
        if self.state_manager.triage_mode:
            feedback += f" | Triage score: {final_triage_score:.3f}"
        if chains:
            feedback += f" | Attack chains: {', '.join(chains)}"
        if self.state_manager.chain_complete:
            feedback += f" | Chain objective '{self.state_manager.chain_objective['name']}' COMPLETE"

        return feedback, episode_score

    def _handle_add_note(self, payload):
        note = payload.get("note", "")
        if note:
            self.state_manager.add_note(note)
            return f"Note recorded: {note[:80]}"
        return "Empty note ignored."

    def _terminal_result(self, feedback):
        episode_score = self.state_manager.compute_episode_score_cached(
            chain_bonus=0.0,
            use_precision_scoring=ENABLE_PRECISION_SCORING,
            current_step=self.state_manager.step_number,
            max_steps=self.active_task.max_steps,
        )

        live_chain_status = self.state_manager.get_live_chain_status()

        return StepResult(
            observation=Observation(
                files=self.state_manager.get_visible_file_contents(),
                current_findings=self.state_manager.findings,
                step_number=self.state_manager.step_number,
                task_id=self.active_task.task_id,
                feedback=feedback,
                remaining_steps=0,
                active_insights=self.state_manager.active_insights,
                suspicious_files=self.state_manager.suspicious_files,
                chain_objective=self.state_manager.chain_objective,
                chain_progress=self.state_manager.chain_steps_found,
                chain_complete=self.state_manager.chain_complete,
                chain_ordered=self.state_manager.chain_ordered,
                triage_mode=self.state_manager.triage_mode,
                triage_score=0.0,
                severity_coverage={},
                priority_budget=0,
                live_chain_status=live_chain_status,
            ),
            reward=0.0,
            done=True,
            info={
                "episode_score": episode_score,
                "findings_count": len(self.state_manager.findings),
                "ground_truth_count": len(self.active_task.ground_truth),
                "live_chain_status": live_chain_status,
                "chain_progress": self.state_manager.chain_steps_found,
                "chain_complete": self.state_manager.chain_complete,
            },
        )

    def _load_task(self, task_id: int):
        if task_id == 1:
            from environment.tasks.task1_single_file import Task1SingleFile
            return Task1SingleFile()
        elif task_id == 2:
            from environment.tasks.task2_multifile import Task2MultiFile
            return Task2MultiFile()
        elif task_id == 3:
            from environment.tasks.task3_realworld import Task3RealWorld
            return Task3RealWorld()
        else:
            raise ValueError("Invalid task_id")