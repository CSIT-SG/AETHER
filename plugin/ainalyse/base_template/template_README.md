# Important notes

## Design Principles

- Primarily, we adopt an MVC (Model-View-Controller) style (simply VC if there's no persistent model)
- Keep all backend code in the backend folder and all system prompts into the prompts folder. Backend code includes:
    - Auxiliary LLM functions
    - Auxiliary MCP calls
    - Gatherer-Annotator tools
- Try to bundle backend functions into one when using the functionalities in the controller. For example, suppose we want to perform a custom annotation feature on multiple selected functions:
    - in the backend,
        - `retrieve_function_choices()`
        - `mcp_gatherer()`
        - `perform_LLM_annotate()`
        - `annotate_to_ida()`
        - `write_to_LLM_memory()`
        - `flush_function_choices()`
    - then we write later on
        ```
        def custom_annotate_select_functions() :
            retrieve_function_choices()
            print("Function choices retrieved")
            mcp_gatherer()
            print("mcp gatherer successful")
            perform_LLM_annotate()
            print("LLM annotation complete")
            annotate_to_ida()
            print("annotation successfully written to IDA")
            write_to_LLM_memory()
            print("LLM memory updated")
            flush_function_choices()
        ```
    - Finally in the controller, we merely import `custom_annotation_select_functions()` and use this *abstracted* function.
- When to create new files to separate code may be unclear at times. As a rule of thumb, if we have a functionality that appears in another interface, we shall separate this functionality. With some leeway, separation may be considered if the code gets too long (about a thousand lines or so).

## Complications

The base template is certainly not perfect for all features, but rather exists to encourage good code practices. Below are some possible complications that one may run into while using this template:
- **Feature without view**: The UI folder may be deleted
- **Many controllers**: Create a Controllers folder (when it begins to clutter)