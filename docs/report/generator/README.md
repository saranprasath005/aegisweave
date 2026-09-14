# Report generator

The Word and web reports in `docs/report/` are generated, not hand-edited: every number comes from
`report_data.json`, which `extract.py` computes from the committed result files, the live-replay
databases, the IoT-23 logs, the latest verification report and the test suite.

Run from this directory after the experiments, verification script and live replay have been run:

```bash
../../../.venv/Scripts/python extract.py
```

```bash
npm install
```

```bash
node build_docx.js
```

```bash
powershell -ExecutionPolicy Bypass -File finalize.ps1
```

```bash
node build_html.js
```

`finalize.ps1` needs Microsoft Word. It fills in the table of contents, writes
`../AegisWeave_Project_Report.docx` and `.pdf`, and renders pages to `pages/` for checking.
Report text lives in `content.js`; edit it there so both formats stay in sync.
Cover-page placeholders (student, institution, supervisor) are meant to be filled in the final Word file.
