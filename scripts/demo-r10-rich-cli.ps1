param(
    [ValidateSet("interactive", "boot", "core", "flow", "status")]
    [string]$Mode = "interactive"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Invoke-Moxi {
    param([string[]]$MoxiArgs)
    & cargo run -p moxi-cli --bin moxi --locked -- @MoxiArgs
}

switch ($Mode) {
    "interactive" {
        & cargo run -p moxi-cli --bin moxi --locked
    }
    "boot" {
        Invoke-Moxi @("tui", "--width", "120", "--height", "32", "--keys", "boot,q")
    }
    "core" {
        Invoke-Moxi @("tui", "--width", "132", "--height", "34", "--keys", "core,q")
    }
    "flow" {
        Invoke-Moxi @(
            "tui",
            "--width",
            "132",
            "--height",
            "38",
            "--keys",
            "boot,enter,enter,enter,type:i,type:n,type:s,type:p,type:e,type:c,type:t,enter,r,r,r,type:/,type:c,type:o,type:n,enter,type:/,type:s,type:a,type:v,type:e,enter,type:/,type:r,type:e,type:s,type:u,type:m,type:e,enter,q"
        )
    }
    "status" {
        $SnapshotPath = Join-Path ([System.IO.Path]::GetTempPath()) ("moxi-r10-status-{0}.json" -f [guid]::NewGuid())
        $Snapshot = @'
{
  "graph": {
    "graph_id": "graph_detail",
    "goal": "read project",
    "path": "task_path",
    "task_count": 1,
    "completed_count": 0,
    "running_count": 0,
    "blocked_count": 1,
    "awaiting_approval_count": 1,
    "failed_count": 0,
    "is_complete": false
  },
  "planner": null,
  "tasks": [{
    "task_id": "task_1",
    "skill_id": "skill.file.read",
    "capability_id": "file.read",
    "target": {
      "resource_type": "file",
      "resource_ref": "README.md"
    },
    "state": "awaiting_approval",
    "last_stage": "awaiting_approval",
    "progress": 0.5,
    "message": "waiting for approval",
    "idempotency_key": null,
    "retry_safe": null,
    "blocker": "awaiting_approval",
    "updated_at": "2026-05-26T05:30:00Z"
  }],
  "attempts": [],
  "adoption_probes": [],
  "events": [{
    "event_id": "event_1",
    "graph_id": "graph_detail",
    "run_id": "run_1",
    "task_id": "task_1",
    "stage": "awaiting_approval",
    "message": "waiting for approval",
    "progress": 0.5,
    "timestamp": "2026-05-26T05:30:00Z"
  }],
  "resume_plan": {
    "graph_id": "graph_detail",
    "completed_task_ids": [],
    "ready_task_ids": [],
    "blocked_task_ids": ["task_1"],
    "running_task_ids": [],
    "awaiting_approval_task_ids": ["task_1"],
    "failed_task_ids": [],
    "blockers": {
      "task_1": "awaiting_approval"
    },
    "adoption_recommendations": {},
    "running_task_policy": "require_inspection",
    "is_complete": false
  },
  "event_cursor": 3,
  "policy_profile": {
    "profile_id": "shell.ide.readonly",
    "allowed_capabilities": ["file.read"],
    "allow_fast_path": false,
    "allow_task_path": true,
    "allow_trusted_execution_path": false,
    "allow_skills": true,
    "allow_running_task_retry": false,
    "max_tasks_per_graph": 8
  }
}
'@
        try {
            Set-Content -LiteralPath $SnapshotPath -Value $Snapshot -Encoding UTF8
            Invoke-Moxi @("status", "--query", "--surface", "ide", "--graph", "graph_detail", "--input", $SnapshotPath, "--text")
        }
        finally {
            Remove-Item -LiteralPath $SnapshotPath -Force -ErrorAction SilentlyContinue
        }
    }
}
