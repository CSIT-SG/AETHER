Create, update, or delete objectives inside a plan. See `manage_plans`.

Use the action to select the operation.

Required payload fields depend on the action:
- create: `plan_id`, `text`, optional `status`
- update: `plan_id`, `objective_id`, plus any fields to change
- delete: `plan_id`, `objective_id`

To inspect objectives, read the parent plan with the plan tool.