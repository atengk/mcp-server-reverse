"""mcp_server_reverse 模块直接执行入口 (python -m mcp_server_reverse)

@author Ateng
@since 2026-10-13
"""

import sys

from mcp_server_reverse.cli import main

if __name__ == "__main__":
    sys.exit(main())
