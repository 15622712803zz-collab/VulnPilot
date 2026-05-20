# VulnPilot

VulnPilot is an automated Vulhub penetration-testing framework for single-target and batch experiments. It drives reconnaissance, vulnerability analysis, and exploitation, then produces reports that summarize the three testing phases for experiment comparison.

## Features

- Single Vulhub target execution through `main.py`.
- Batch Vulhub execution from a target list through `scripts/batch_vulhub_test.py`.
- Three-phase reporting: intelligence collection, vulnerability analysis, and exploitation.
- Exploitation-success judgment based on concrete evidence such as command execution, file read, authentication bypass, shell output, or application-specific impact. A synthetic flag is not required.
- Ablation switches for process-notebook and skills modules.

## Installation

```bash
uv sync
```

Copy the configuration template and fill in your local keys and paths:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

## Configuration

Important variables in `.env`:

- `LLM_PROVIDER`: `deepseek` or `openai`.
- `DEEPSEEK_API_KEY` / `OPENAI_API_KEY`: model API credentials.
- `LLM_MODEL_NAME`: model name used by the selected provider.
- `DOCKER_CONTAINER_NAME`: optional Kali container name.
- `CHALLENGE_BASE_URL` and `CHALLENGE_API_TOKEN`: optional evaluation API integration.
- `SANDBOX_ENABLED`: optional Microsandbox backend switch.

## Single Vulhub Target

```bash
uv run python main.py -vulhub activemq/CVE-2016-3088 --vulhub-dir D:/vulhub
```

Optional retry:

```bash
uv run python main.py -vulhub activemq/CVE-2016-3088 --retry 1 --vulhub-dir D:/vulhub
```

Logs are written to `logs/vulnpilot_YYYYMMDD_HHMMSS.log` during execution.

## Batch Vulhub Test

Create a target list such as `scripts/targets.txt`:

```text
activemq/CVE-2016-3088
cacti CVE-2022-46169
uwsgi CVE-2018-7490
```

Run the batch test:

```bash
uv run python scripts/batch_vulhub_test.py --targets scripts/targets.txt --retry 1 --vulhub-dir D:/vulhub
```

The default batch report path is `logs/batch_test/batch_report_YYYYMMDD_HHMMSS.md`.

## Three-Phase Reports

The report records each target in three phases:

1. Intelligence collection: target startup, service discovery, endpoint observations, and version hints.
2. Vulnerability analysis: CVE reasoning, affected component confirmation, and candidate exploit path.
3. Exploitation: concrete exploitation attempt and success/failure evidence.

For existing logs, generate a standalone phase report:

```bash
uv run python scripts/generate_phase_report.py logs/vulnpilot_YYYYMMDD_HHMMSS.log
```

## Ablation Experiments

Disable process notebook:

```bash
uv run python scripts/batch_vulhub_test.py --targets scripts/targets.txt --disable-process-notebook --output logs/batch_test/no_notebook_YYYYMMDD_HHMMSS.md
```

Disable skills:

```bash
uv run python scripts/batch_vulhub_test.py --targets scripts/targets.txt --disable-skills --output logs/batch_test/no_skills_YYYYMMDD_HHMMSS.md
```

Both ablation modes keep the same three-phase report format for comparison.

## Output Layout

- `logs/vulnpilot_*.log`: per-run execution logs.
- `logs/phase_reports/*.md`: single-log three-phase reports.
- `logs/batch_test/*.md`: batch test reports.

These runtime outputs are ignored by `.gitignore` and are not included in the submission source tree.