#!/usr/bin/env python3
"""
pdf_to_text.py

Convert a single PDF or all PDFs in a directory to .txt files using PyMuPDF (fitz).

Usage:
    python pdf_to_text.py /path/to/file.pdf
    python pdf_to_text.py /path/to/pdf_directory
    python pdf_to_text.py /path/to/pdf_directory --recursive
    python pdf_to_text.py /path/to/file.pdf --mode markdown
"""

import argparse
from pathlib import Path
import sys

import fitz  # PyMuPDF


def extract_pdf_to_text(pdf_path: Path, mode: str = "text") -> str:
    """
    Extract text from a PDF page by page.

    Supported modes:
        - text
        - markdown
    """
    extracted_parts = []

    try:
        with fitz.open(pdf_path) as doc:
            for i, page in enumerate(doc, start=1):
                page_text = page.get_text(mode)
                extracted_parts.append(f"\n--- PAGE {i} ---\n")
                extracted_parts.append(page_text)
    except Exception as e:
        raise RuntimeError(f"Failed to process '{pdf_path}': {e}")

    return "".join(extracted_parts)


def convert_pdf(pdf_path: Path, overwrite: bool = False, mode: str = "text") -> None:
    """
    Convert a single PDF to a .txt file in the same directory.
    """
    txt_path = pdf_path.with_suffix(".txt")

    if txt_path.exists() and not overwrite:
        print(f"[!] Skipping existing file: {txt_path}")
        return

    text = extract_pdf_to_text(pdf_path, mode=mode)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(text)

    print(f"[+] Wrote: {txt_path}")


def get_pdf_files(target: Path, recursive: bool = False) -> list[Path]:
    """
    Return a list of PDF files from a single file or directory.
    """
    if target.is_file():
        if target.suffix.lower() != ".pdf":
            raise ValueError(f"File is not a PDF: {target}")
        return [target]

    if target.is_dir():
        if recursive:
            return sorted(p for p in target.rglob("*.pdf") if p.is_file())
        return sorted(p for p in target.glob("*.pdf") if p.is_file())

    raise ValueError(f"Target does not exist: {target}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a PDF or all PDFs in a directory to .txt using PyMuPDF."
    )
    parser.add_argument(
        "target",
        help="Path to a PDF file or a directory containing PDF files.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively search subdirectories for PDFs when target is a directory.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing .txt files.",
    )
    parser.add_argument(
        "--mode",
        choices=["text", "markdown"],
        default="text",
        help="Extraction mode to use with PyMuPDF.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target).expanduser().resolve()

    try:
        pdf_files = get_pdf_files(target, recursive=args.recursive)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1

    if not pdf_files:
        print("[-] No PDF files found.", file=sys.stderr)
        return 1

    failures = 0

    for pdf_file in pdf_files:
        try:
            convert_pdf(pdf_file, overwrite=args.overwrite, mode=args.mode)
        except Exception as e:
            failures += 1
            print(f"[-] {e}", file=sys.stderr)

    if failures:
        print(f"[!] Completed with {failures} failure(s).", file=sys.stderr)
        return 2

    print("[+] Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
