import contextlib
import io

from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result


class ExecuteIDAPython(Capability):
    @property
    def name(self) -> str:
        return "execute_idapython"

    def execute(self, code: str) -> Result[str]:
        """Executes a given Python code snippet in the IDA environment.

        Args:
            code: A string containing the Python code to execute.

        Returns:
            A Result object containing the output of the executed code or an error message.
        """
        try:
            # we need to inject this current module's globals into the exec environment to allow access to IDA's API
            # do not pass globals directly to exec, as it will overwrite the current module's globals
            global_scope = globals().copy()

            # Redirect stdout to capture print statements
            sysout = io.StringIO()
            with contextlib.redirect_stdout(sysout):
                exec(code, global_scope)

            return Ok(sysout.getvalue())
        except Exception as e:
            self.logger.exception("Failed to execute IDAPython code: %s", e)
            return Err(str(e))
