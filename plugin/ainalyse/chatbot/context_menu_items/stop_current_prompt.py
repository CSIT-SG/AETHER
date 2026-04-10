class StopCurrentPrompt() :
    def __init__(self) : pass

    @staticmethod
    def _stop_current_prompt(CBController) :
        """Stops current prompt and breaks the thinking loop"""
        if (not CBController.is_thinking) : return
        CBController._cleanup()
        CBController._add_message("SYSTEM", "Force Stop Complete")
        print("[AETHER Chatbot] Force stop complete. Ready for new user query.")
        CBController.is_thinking = False
        CBController.force_stop = True