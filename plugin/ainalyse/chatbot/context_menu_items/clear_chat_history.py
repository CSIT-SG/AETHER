class ClearChatHistory() :
    def __init__(self) : pass

    @staticmethod
    def _clear_chat_history(CBController) :
        CBController.PERSISTENT_MESSAGE_LOG.clear()
        CBController.history_view.clear()
        CBController.agent_state.clear_memory()
        CBController.agent_state.conversation_history.clear()