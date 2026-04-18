

# Here is the source code of all agents

It includes **SWEagent, OpenHands, and ClaudeCode**. You can navigate into the corresponding folder and run our experiments according to its `README.md`.

# The experimental setup is as follows
| Experiment  | Description                                                 | loc   | knowledge | Test feedback |
| ----------- | ----------------------------------------------------------- | ----- | --------- | ------------- |
| 1 (default) | Only location information is provided                       | w.    | w.        | w\.o.         |
| 2           | Adds feedback for testing                                   | w.    | w.        | w.            |
| 3           | Adds feedback for testing, but without location information | w\.o. | w.        | w.            |
| 4           | No knowledge information provided                           | w.    | w\.o.     | w\.o.         |
| 5           | Blackbox                                                    | w\.o. | w.        | w\.o          |

### Execution Constraints
Agents run inside an **isolated Docker environment** with a limited number of tool calls.

### File Visibility
Agents operate in `/workspace/repo_name` as the working directory; evaluation test patches are moved beforehand to avoid leakage.

### Feedback Scope
Agents only receive **PoC-based feedback**, and no unit test results are provided during execution.