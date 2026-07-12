# Failed Workflow Analysis - Pod Log Capture

## Context

This analysis was performed as part of bead `bf-41nd8` to capture detailed logs from a failed pod in the `iad-ci` Argo Workflows cluster.

## Challenge: Immediate Pod Deletion

The `sigil-ci` WorkflowTemplate uses `podGC: OnPodCompletion`, which means pods are deleted immediately when they finish. This prevents log capture after the fact unless you catch the pod while it's running.

## Workflow Analysis Methods

### Method 1: Catch Logs During Execution

To capture logs from a failed workflow, you must stream them **while the workflow is running**:

```bash
# Watch for workflow pods in real-time
kubectl --kubeconfig=/home/coding/.kube/iad-ci.kubeconfig \
  get pods -n argo-workflows -l workflows.argoproj.io/workflow=<name> -w

# Stream logs from a specific pod (must be caught WHILE running)
kubectl --kubeconfig=/home/coding/.kube/iad-ci.kubeconfig \
  logs -n argo-workflows <pod-name> -c main -f
```

### Method 2: Submit Debug Workflow

Submit a debug workflow with `podGC: OnWorkflowCompletion` override:

```bash
kubectl --kubeconfig=/home/coding/.kube/iad-ci.kubeconfig create -f - <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: sigil-ci-debug-
  namespace: argo-workflows
spec:
  workflowTemplateRef:
    name: sigil-ci
  # Override podGC to keep pods for analysis
  podGC:
    strategy: OnWorkflowCompletion
EOF
```

This keeps pods until the entire workflow completes, giving you time to capture logs.

### Method 3: Extract Failure Details from Workflow Status

When pods are deleted, extract failure information from the workflow object itself:

```bash
# Get workflow phase and error message
kubectl --kubeconfig=/home/coding/.kube/iad-ci.kubeconfig \
  get workflow <name> -n argo-workflows \
  -o jsonpath='{.status.phase} - {.status.message}'

# Get per-node failure details
kubectl --kubeconfig=/home/coding/.kube/iad-ci.kubeconfig \
  get workflow <name> -n argo-workflows -o json | python3 -c "
import json, sys
w = json.load(sys.stdin)
for node in w['status']['nodes'].values():
    if node.get('phase') in ('Failed', 'Error'):
        print(node['displayName'], '-', node['phase'])
        print('  msg:', node.get('message', ''))
"
```

## Current Cluster Status

As of 2026-07-12, the `iad-ci` cluster has:

- **62 total workflows** in history
- **56 failed workflows** (primarily armor-build failures)
- **0 sigil-ci workflows** currently present (cleaned up)

### Recent Failure Pattern

Most recent failures are `armor-build` workflows with child pod failures:
```
armor-build-274n5 - child 'armor-build-274n5-3073961046' failed
armor-build-4j44f - child 'armor-build-4j44f-612861817' failed
armor-build-4tckq - child 'armor-build-4tckq-1485241907' failed
```

## Limitation Discovered

**Pod logs are not available after workflow completion** due to:
1. `podGC: OnPodCompletion` setting in the WorkflowTemplate
2. Pods are deleted immediately when they finish
3. No persistent log storage is configured

This means:
- You cannot retrieve logs from completed workflows
- You must catch pods while running or use debug mode
- Workflow status only shows exit codes, not detailed logs

## Recommendations

### For Future Debugging

1. **Use debug workflow mode** for reproducing failures:
   ```bash
   # Submit with podGC override
   kubectl create -f - <<EOF
   apiVersion: argoproj.io/v1alpha1
   kind: Workflow
   metadata:
     generateName: sigil-ci-debug-
     namespace: argo-workflows
   spec:
     workflowTemplateRef:
       name: sigil-ci
     podGC:
       strategy: OnWorkflowCompletion
   EOF
   ```

2. **Stream logs in real-time** for long-running workflows:
   ```bash
   # Watch workflow and stream logs as it runs
   kubectl get wf -w -n argo-workflows &
   kubectl logs -f -n argo-workflows -l workflows.argoproj.io/workflow=<name> -c main
   ```

3. **Check workflow status** for failure patterns:
   ```bash
   # List recent failures
   kubectl get workflows -n argo-workflows --field-selector=status.phase=Failed \
     --sort-by=.metadata.creationTimestamp | tail -10
   ```

### For CI/CD Pipeline

Consider adding these improvements to the `sigil-ci` WorkflowTemplate:

1. **Conditional podGC strategy**:
   ```yaml
   podGC:
     strategy: OnWorkflowCompletion  # Keep pods on failure
     strategy: OnPodSuccess         # Delete on success, keep on failure
   ```

2. **Log aggregation**:
   - Stream workflow logs to a persistent log store (ELK, Loki, CloudWatch)
   - Attach logs as workflow artifacts

3. **Failure notification**:
   - Configure Argo Workflows to send alerts on failure
   - Include workflow status and failure reasons in notifications

## Conclusion

For bead `bf-41nd8`, **pod logs are unavailable** because:
- The workflow has already completed
- Pods were deleted immediately due to `podGC: OnPodCompletion`
- No persistent log storage exists in the current setup

To capture logs from failed workflows in the future, use **debug workflow mode** or **stream logs in real-time** during execution.
