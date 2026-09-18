Create, read, update, delete, and list plans in the shared planning store.

Use the action to select the operation.

Required payload fields depend on the action:
- create: `title`, optional `description`, optional `status`
- read: `plan_id`
- update: `plan_id`, plus any fields to change
- delete: `plan_id`
- list: optional `status`

Read and list return full plan models, including objectives.