import threading

from flask import _app_ctx_stack, has_app_context

APP_CONTEXT_ERROR = 'Running outside of Flask AppContext.'

class AppContextThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not has_app_context():
            raise RuntimeError(APP_CONTEXT_ERROR)
        self.app_ctx = _app_ctx_stack.top

    def run(self):
        try:
            self.app_ctx.push()
            super().run()
        finally:
            self.app_ctx.pop()
