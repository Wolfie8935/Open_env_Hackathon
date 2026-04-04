# Security Vulnerability Scanner — Architecture

End-to-end view of deployment, the OpenEnv HTTP server, the Python environment core, and the baseline inference agent (LLM + deterministic scanner).

---

## 1. System context (deployment & actors)

```mermaid
flowchart TB
    subgraph external [External]
        HF[Hugging Face Space]
        Judge[Eval / CI runner]
        LLM[(OpenAI-compatible API)]
    end

    subgraph container [Docker image :7860]
        API[FastAPI main.py]
        ENV[SecurityScannerEnv]
        API --> ENV
    end

    HF -->|git build| container
    Judge -->|POST /reset /step| API
    Judge -->|python inference.py| INF[inference.py on host or job]
    INF -->|HTTP JSON| API
    INF -->|chat.completions| LLM
```

---

## 2. HTTP surface (OpenEnv contract)

```mermaid
flowchart LR
    subgraph client [Clients]
        INF[inference.py]
        CURL[curl / validate script]
    end

    subgraph fastapi [FastAPI :7860]
        H[/health/]
        T[/tasks/]
        R[/reset/]
        S[/step/]
        ST[/state/]
        V[/validate/]
    end

    INF --> R
    INF --> S
    INF --> ST
    CURL --> R
    CURL --> H
```

---

## 3. Environment core (inside `SecurityScannerEnv`)

```mermaid
flowchart TB
    subgraph reset_path [reset task_id]
        LT[_load_task]
        SM[StateManager.initialize]
        SA[security_analysis: graph static dataflow exploit chains]
        LT --> SM
        LT --> SA
        SM -->|task 3: reveal all files| SM
    end

    subgraph step_path [step action]
        GR[Grader + reward.compute_step_reward]
        OB[Build Observation]
        TR[Triage / precision / evidence flags]
        GR --> OB
        OB --> TR
    end

    SM2[StateManager]
    reset_path --> SM2
    step_path --> SM2
```

---

## 4. Task & data layout

```mermaid
flowchart LR
    subgraph tasks [environment/tasks]
        T1[Task1SingleFile]
        T2[Task2MultiFile]
        T3[Task3RealWorld]
    end

    subgraph data [environment/data]
        D1[task1/]
        D2[task2/]
        D3[task3/]
    end

    T1 --> D1
    T2 --> D2
    T3 --> D3

    subgraph graders [environment/graders]
        G1[grader1]
        G2[grader2]
        G3[grader3]
    end

    T1 -.-> G1
    T2 -.-> G2
    T3 -.-> G3
```

---

## 5. Inference episode sequence (one LLM task)

```mermaid
sequenceDiagram
    participant I as inference.py
    participant H as httpx → ENV_BASE_URL
    participant API as FastAPI
    participant E as SecurityScannerEnv
    participant L as OpenAI client

    I->>H: POST /reset task_id
    H->>API: JSON body
    API->>E: reset(task_id)
    E-->>API: Observation
    API-->>I: observation JSON

    Note over I: stdout [START] task env model

    loop until done or max steps
        I->>L: chat.completions.create
        L-->>I: assistant JSON action
        Note over I: interceptors duplicate trap mark_complete guard
        I->>H: POST /step action
        H->>API: Action
        API->>E: step(action)
        E-->>API: StepResult obs reward done info
        API-->>I: JSON
        Note over I: stdout [STEP] per env step
    end

    Note over I: stdout [END] success steps score rewards
    Note over I: stderr human logs + summary
```

---

## 6. Dual baseline flow (deterministic then LLM)

```mermaid
flowchart TB
    START([main]) --> HEALTH{GET /health}
    HEALTH -->|fail| STOP([exit])
    HEALTH -->|ok| DB[run_deterministic_baseline]
    DB -->|POST /reset /step| API[(FastAPI env)]

    DB --> KEY{HF_TOKEN / API key?}
    KEY -->|no| SUM[stderr summary]
    KEY -->|yes| LOOP[for task_id 1..3]
    LOOP --> RT[run_task]
    RT -->|stdout| OUT["[START] [STEP] [END]"]
    RT -->|stderr| LOG[human trace]
    RT -->|POST /reset /step| API
    LOOP --> SUM
    SUM --> JSON[inference_results.json]
```

---

## 7. Configuration & submission knobs

```mermaid
flowchart LR
    subgraph envvars [Environment variables]
        HF[HF_TOKEN / OPENAI_API_KEY]
        APIU[API_BASE_URL]
        MOD[MODEL_NAME]
        EBU[ENV_BASE_URL]
        IMG[LOCAL_IMAGE_NAME optional]
    end

    subgraph files [Repo]
        OY[openenv.yaml]
        CFG[environment/config.py]
    end

    INF[inference.py] --> envvars
    ENV[SecurityScannerEnv] --> CFG
    VAL[openenv validate] --> OY
```

---

*Generated for Team Suika — OpenEnv Security Vulnerability Scanner.*
