# AI Risk Scanner (prototype v0.1)

Tests a chatbot with 20 security checks, grades the replies, and makes a PDF report.
Only the Python standard library is needed, except `reportlab` for the PDF.

**Only test chatbots you own or have written permission to test.**

## Files
- `attack_library_v0.1.json`: the 20 tests (OWASP LLM Top 10 + MITRE ATLAS + compliance tags)
- `scanner.py`: runs the tests and grades the replies
- `report_generator.py`: makes a PDF from `scan_results.json`
- `test_bot.py` + `acme_system_prompt.txt`: a test chatbot you own (AcmeBot)

## 1. Quick check, no keys needed
    python3 scanner.py --authorized --demo

## 2. Local end-to-end test, no keys needed
Terminal 1:

    python3 test_bot.py --offline

Terminal 2:

    python3 scanner.py --authorized --heuristic-judge \
      --target-url http://127.0.0.1:8000/v1/chat/completions
    pip install reportlab
    python3 report_generator.py scan_results.json -o report.pdf --company "AcmeBot test"

## 3. Real scan (AI replies + AI judge)
    export ANTHROPIC_API_KEY="your key"
    python3 test_bot.py                      # terminal 1, real Claude behind AcmeBot
    python3 scanner.py --authorized \
      --target-url http://127.0.0.1:8000/v1/chat/completions   # terminal 2

Never commit API keys. Add them as environment variables or Codespaces secrets.

## Known limits
- The rule-based judge is crude. Only the AI judge is good enough for customers.
- Hindi text in PDF excerpts shows as "?" until a Unicode font is added.
- Ownership verification (DNS / file check) is not built yet.
