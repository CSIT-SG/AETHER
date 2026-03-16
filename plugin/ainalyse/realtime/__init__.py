"""
Realtime analysis module for AETHER.
Provides fast look and custom prompt re-annotation functionality.
"""

from .dialog import CustomPromptDialog
from .handlers import CustomPromptReAnnotateHandler, FastLookHandler, StripAIAnnotationsHandler
from .realtime import run_custom_prompt_analysis, run_fast_look_analysis

__all__ = [
    'run_fast_look_analysis',
    'run_custom_prompt_analysis', 
    'FastLookHandler',
    'CustomPromptReAnnotateHandler',
    'StripAIAnnotationsHandler',
    'CustomPromptDialog'
]
