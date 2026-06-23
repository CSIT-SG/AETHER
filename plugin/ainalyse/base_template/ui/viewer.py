import ida_kernwin
from ..controller import TemplateController

TEMPLATE_VIEW_TITLE = "Feature!"

class TemplateViewer :
    def __init__(self, caption = "Feature caption") :
        self.title = TEMPLATE_VIEW_TITLE
        self.caption = caption
        self.controller = TemplateController()

def show_template_viewer(caption) :
    widget = ida_kernwin.find_widget(TEMPLATE_VIEW_TITLE)
    if widget :
        ida_kernwin.activate_widget(widget, True)
    else :
        view = TemplateViewer(caption = caption)
        view.Show()