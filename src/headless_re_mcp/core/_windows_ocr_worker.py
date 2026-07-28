import json
import sys

from headless_re_mcp.core.ui_ocr import _ocr_bmp_windows_inprocess


def main() -> None:
    path, language = sys.argv[1], sys.argv[2]
    print(json.dumps(_ocr_bmp_windows_inprocess(path, language=language), ensure_ascii=False))


if __name__ == "__main__":
    main()
