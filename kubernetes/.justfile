timeout := "300s"

# List tasks
default:
  just --list

# Get all pods in an errored state
erroneous-pods:
  kubectl get pods -A | grep -Ev 'Running|Completed'
