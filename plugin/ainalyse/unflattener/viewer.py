import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines

from .storage import load_ai_deobfs
from .syntax_highlighter import highlight_c_code

# --- Constants ---
AI_DEOBFS_VIEW_TITLE = "AI Unflattener"

# --- Global State for Viewers ---
g_ai_deobfs_viewers = {}

# --- Use PyQt for UI components ---
try:
    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget
except ImportError:
    try:
        from PySide2.QtCore import Qt
        from PySide2.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget
    except ImportError:
        print("[AInalyse] [AI Unflatten] Could not import PyQt5 or PySide2. Falling back to basic viewer.")

# --- Hexrays Hook for Synchronized Scrolling ---
class AIDeobfsScrollHooks(ida_hexrays.Hexrays_Hooks):
    """Hooks into Hex-Rays events to detect cursor position changes for scrolling."""
    
    def curpos(self, vdui):
        """Called when cursor position changes in pseudocode view."""
        # Only update if synchronized scrolling is enabled
        form_instance = g_ai_deobfs_viewers.get(AI_DEOBFS_VIEW_TITLE)
        if form_instance and form_instance.sync_scrolling_enabled:
            try:
                func_addr = hex(vdui.cfunc.entry_ea)
                current_form_addr = form_instance.current_func_addr
                
                # Only sync scroll if the addresses match
                if current_form_addr and current_form_addr.lower() == func_addr.lower():
                    # Get current line number and total lines
                    cpos = vdui.cpos
                    current_line = cpos.lnnum
                    total_lines = len([line for line in vdui.cfunc.get_pseudocode()])
                    
                    if total_lines > 0 and current_line > 0:
                        # Update scroll position
                        form_instance.sync_scroll_position(current_line, total_lines)
            except Exception as e:
                print(f"[AInalyse] [AI Unflatten] Error in scroll sync: {e}")
        return 0

# Global hooks instance
_scroll_hooks = None

def get_function_name_safe(func_addr_str: str) -> str:
    """Safely get function name from main thread."""
    def _get_name_sync():
        try:
            func_addr_int = int(func_addr_str, 16)
            return ida_funcs.get_func_name(func_addr_int) or f"sub_{func_addr_int:x}"
        except Exception as e:
            print(f"[AInalyse] [AI Unflatten] Error getting function name for {func_addr_str}: {e}")
            return f"sub_{int(func_addr_str, 16):x}"
    
    # Always use execute_sync
    try:
        result = ida_kernwin.execute_sync(_get_name_sync, ida_kernwin.MFF_READ)
        if isinstance(result, str):
            return result
        return f"sub_{int(func_addr_str, 16):x}"
    except Exception as e:
        print(f"[AInalyse] [AI Unflatten] Execute_sync function name lookup failed: {e}")
        return f"sub_{int(func_addr_str, 16):x}"

class AIDeobfsViewer(ida_kernwin.simplecustviewer_t):
    """Custom viewer for AI deobfuscation display."""
    
    def __init__(self):
        super(AIDeobfsViewer, self).__init__()
        self.current_func_addr = None
        self.is_generating = False
        self.error_message = None
        self.content_lines = []
        self.current_scroll_pos = 0

    def Create(self, title):
        """Creates the custom viewer window."""
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            print("[AInalyse] [AI Unflatten] Failed to create custom viewer!")
            return False
        return True

    def GetOptions(self):
        """Return viewer options to show line numbers."""
        return ida_kernwin.simplecustviewer_t.GetOptions(self) | ida_kernwin.CVF_SHOWLINENO

    def SetFunctionAddr(self, func_addr: str):
        """Set the current function address and update display."""
        self.current_func_addr = func_addr
        self.error_message = None  # Reset error when changing function
        self.UpdateDisplay()

    def OnDblClick(self, shift):
        # Get the line under the cursor
        line = self.GetCurrentLine()
        if not line:
            return 0

        # Look for something that looks like a hex EA
        import re
        m = re.search(r"0x([0-9A-Fa-f]+)", line)
        if m:
            ea = int(m.group(1), 16)
            # Jump to the EA if it's mapped
            ida_kernwin.jumpto(ea)
        return 1  # signal that the click was handled

    def UpdateDisplay(self):
        """Update the display based on current function address."""
        if not self.current_func_addr:
            self.ShowMessage("No function selected")
            return
            
        # If there's an error message, show it instead of loading
        if self.error_message:
            self.ShowMessage(self.error_message)
            return

        # Try multiple attempts to load the data
        existing_deobfs = None
        for attempt in range(3):  # Try up to 3 times
            existing_deobfs = load_ai_deobfs(self.current_func_addr)
            
            if existing_deobfs:
                break
            elif attempt < 2:  # Don't sleep on the last attempt
                import time
                time.sleep(0.1)  # Brief pause before retry
        
        if self.is_generating:
            self.ShowMessage("AI unflattening in progress, please wait...\n\nThis may take a while for large functions or complex code.")
        elif existing_deobfs and isinstance(existing_deobfs, str) and len(existing_deobfs) > 0:
            self.ShowDeobfuscation(existing_deobfs)
        else:
            self.ShowMessage("No AI unflattened pseudocode available for this function.\n\nUse 'AI Unflatten' from the context menu to create one.")

    def SetGenerating(self, generating: bool):
        """Set the generating state and update display."""
        self.is_generating = generating
        if generating:
            self.error_message = None  # Clear error when starting generation
        self.UpdateDisplay()
        
    def SetError(self, error_msg: str):
        """Set an error message to display."""
        self.error_message = error_msg
        self.is_generating = False
        self.UpdateDisplay()

    def ShowMessage(self, message: str):
        """Display a message in the viewer."""
        self.ClearLines()
        self.content_lines = []
        for line in message.split('\n'):
            # Use error color for error messages
            if self.error_message and message == self.error_message:
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_ERROR)
            else:
                colored_line = ida_lines.COLSTR(line, ida_lines.SCOLOR_DNAME)
            self.AddLine(colored_line)
            self.content_lines.append(colored_line)
        self.Refresh()

    def ShowDeobfuscation(self, deobfs_code: str):
        """Display AI deobfuscation code with enhanced C++ syntax highlighting."""
        # Safety check to ensure deobfs_code is actually a string
        if not isinstance(deobfs_code, str):
            deobfs_code = str(deobfs_code) if deobfs_code is not None else "No deobfuscation data available."
        
        self.ClearLines()
        self.content_lines = []
        
        # Add header with comment-style prefix
        func_name = get_function_name_safe(self.current_func_addr)
        header = f"// AI Deobfuscation for {func_name} [{self.current_func_addr}]"
        header_line = ida_lines.COLSTR(header, ida_lines.SCOLOR_AUTOCMT)
        self.AddLine(header_line)
        self.content_lines.append(header_line)
        self.AddLine("")
        self.content_lines.append("")
        
        # Add deobfuscation code with enhanced syntax highlighting
        for line in deobfs_code.split('\n'):
            # Apply syntax highlighting using the dedicated module
            highlighted_line = highlight_c_code(line)
            self.AddLine(highlighted_line)
            self.content_lines.append(highlighted_line)
        
        self.Refresh()
        
    def set_scroll_position(self, line_num, total_lines):
        """Scroll to a position based on line number."""
        if not self.content_lines or total_lines <= 0 or line_num <= 0:
            return
            
        # Calculate position as a percentage through the document
        percentage = line_num / total_lines
        
        # Calculate target line in our content
        target_line = min(len(self.content_lines) - 1, 
                         max(0, int(percentage * len(self.content_lines))))
        
        # Store current position for reference
        self.current_scroll_pos = target_line
        
        # Use Jump to scroll to target line
        self.Jump(target_line, 0, 0)


class AIDeobfsForm(ida_kernwin.PluginForm):
    """Form wrapper that includes controls and the AI deobfuscation viewer."""
    
    def __init__(self):
        super(AIDeobfsForm, self).__init__()
        self.viewer = None
        self.sync_scrolling_enabled = False
        self.chk_sync_scrolling = None
        self.status_label = None
        self.current_func_addr = None
        
        # Install scroll hooks if not already installed
        global _scroll_hooks
        if not _scroll_hooks and ida_hexrays.init_hexrays_plugin():
            _scroll_hooks = AIDeobfsScrollHooks()
            _scroll_hooks.hook()
            print("[AInalyse] [AI Unflatten] Installed scroll sync hooks")

    def OnCreate(self, form):
        """Called when the form is created."""
        self.parent = self.FormToPyQtWidget(form)
        g_ai_deobfs_viewers[AI_DEOBFS_VIEW_TITLE] = self
        
        # Create layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)  # Remove padding around main layout
        layout.setSpacing(2)  # Reduce spacing between widgets
        
        # Add controls at top - use horizontal layout for checkbox and status
        control_layout = QHBoxLayout()
        control_layout.setContentsMargins(5, 2, 5, 2)  # Small margins: left, top, right, bottom
        control_layout.setSpacing(10)  # Reduce spacing between controls
        
        # Sync scrolling checkbox
        self.chk_sync_scrolling = QCheckBox("Sync scrolling with pseudocode view (unstable)")
        self.chk_sync_scrolling.setChecked(self.sync_scrolling_enabled)
        self.chk_sync_scrolling.stateChanged.connect(self.on_sync_changed)
        control_layout.addWidget(self.chk_sync_scrolling)
        
        # Add stretch to push status label to the right
        control_layout.addStretch()
        
        # Status label
        self.status_label = QLabel("Ready")
        control_layout.addWidget(self.status_label)
        
        # Add controls to top of main layout
        controls_widget = QWidget()
        controls_widget.setLayout(control_layout)
        controls_widget.setMaximumHeight(30)  # Limit height of controls area
        layout.addWidget(controls_widget)
        
        # Create viewer container widget
        viewer_container = QWidget()
        layout.addWidget(viewer_container)
        layout.setStretchFactor(viewer_container, 10)  # Give most space to the viewer
        
        # Create the actual viewer
        self.viewer = AIDeobfsViewer()
        if not self.viewer.Create("AIDeobfsViewer_in_Form"):
            print("[AInalyse] [AI Unflatten] Failed to create AI deobfuscation viewer!")
            return
            
        # Get the viewer widget and add to container
        twidget = self.viewer.GetWidget()
        viewer_widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(twidget)
        
        viewer_layout = QVBoxLayout()
        viewer_layout.setContentsMargins(0, 0, 0, 0)  # Remove padding around viewer
        viewer_layout.addWidget(viewer_widget)
        viewer_container.setLayout(viewer_layout)
        
        # Set the main layout
        self.parent.setLayout(layout)
        
    def on_sync_changed(self, state):
        """Handle checkbox state change."""
        self.sync_scrolling_enabled = (state == Qt.Checked)
        self.status_label.setText("Synchronized scrolling " + 
                                ("enabled" if self.sync_scrolling_enabled else "disabled"))
        
    def Show(self, title):
        """Show the form."""
        return super(AIDeobfsForm, self).Show(
            title, 
            options=ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WCLS_CLOSE_LATER
        )

    def OnClose(self, form):
        """Called when form is closed."""
        if AI_DEOBFS_VIEW_TITLE in g_ai_deobfs_viewers:
            del g_ai_deobfs_viewers[AI_DEOBFS_VIEW_TITLE]
        
    # --- Functions to delegate to the viewer ---
    def SetFunctionAddr(self, func_addr):
        self.current_func_addr = func_addr
        if self.viewer:
            self.viewer.SetFunctionAddr(func_addr)
            
    def UpdateDisplay(self):
        if self.viewer:
            self.viewer.UpdateDisplay()
            
    def SetGenerating(self, generating):
        if self.viewer:
            self.viewer.SetGenerating(generating)
            
    def SetError(self, error_msg):
        if self.viewer:
            self.viewer.SetError(error_msg)
            
    def sync_scroll_position(self, current_line, total_lines):
        """Update scroll position based on pseudocode view position."""
        if self.viewer and self.sync_scrolling_enabled:
            self.viewer.set_scroll_position(current_line, total_lines)
            self.status_label.setText(f"Synced: Line {current_line}/{total_lines} ({(current_line/total_lines)*100:.1f}%)")

def show_or_update_ai_deobfs_tab(func_addr: str):
    """Show or update the AI deobfuscation tab for a function."""
    def _show_update_sync():
        try:
            widget = ida_kernwin.find_widget(AI_DEOBFS_VIEW_TITLE)

            if widget:
                # Widget exists, update it
                viewer_instance = g_ai_deobfs_viewers.get(AI_DEOBFS_VIEW_TITLE)
                if viewer_instance:
                    viewer_instance.SetFunctionAddr(func_addr)
                else:
                    print("[AInalyse] [AI Unflatten] [Tab] Widget exists but no viewer instance found in global dict")
            else:
                # Create new form with viewer
                new_form = AIDeobfsForm()
                if new_form.Show(AI_DEOBFS_VIEW_TITLE):
                    new_form.SetFunctionAddr(func_addr)
                else:
                    print("[AInalyse] [AI Unflatten] Failed to create and display the AI deobfuscation form.")
            return True
        except Exception as e:
            print(f"[AInalyse] [AI Unflatten] Error in _show_update_sync: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # Always use execute_sync
    try:
        ida_kernwin.execute_sync(_show_update_sync, ida_kernwin.MFF_WRITE)
    except Exception as e:
        print(f"[AInalyse] [AI Unflatten] Error in show_or_update_ai_deobfs_tab: {e}")
        import traceback
        traceback.print_exc()

def remove_scroll_hooks():
    """Remove scroll hooks when plugin is terminated."""
    global _scroll_hooks
    if _scroll_hooks:
        _scroll_hooks.unhook()
        _scroll_hooks = None
        print("[AInalyse] [AI Unflatten] Removed scroll sync hooks")
