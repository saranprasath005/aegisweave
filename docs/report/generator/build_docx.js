'use strict';
const fs = require('fs');
const path = require('path');
const {
  AlignmentType, BorderStyle, Document, Footer, Header, HeadingLevel, LevelFormat, NumberFormat, Packer, PageBreak,
  PageNumber, Paragraph, ShadingType, Table, TableCell, TableOfContents, TableRow, TextRun, WidthType,
} = require('docx');
const { meta, blocks } = require('./content.js');

const OUT = process.argv[2] || path.join(__dirname, 'raw_report.docx');
const PAGE = { width: 11906, height: 16838 }; // A4
const MARGIN = 1440;
const CONTENT = PAGE.width - 2 * MARGIN;
const INK = '1F2937', ACCENT = '1E3A5F', MUTED = '5B6573', RULE = 'C9D1DB', HEAD_FILL = 'E8EEF5', NOTE_FILL = 'FFF7E6';
const FONT = 'Calibri', MONO = 'Consolas';

// **bold** and `code` inline markup -> runs
function runs(text, base = {}) {
  const out = [];
  for (const part of String(text).split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean)) {
    if (part.startsWith('**')) out.push(new TextRun({ ...base, text: part.slice(2, -2), bold: true }));
    else if (part.startsWith('`')) out.push(new TextRun({ ...base, text: part.slice(1, -1), font: MONO, size: (base.size || 22) - 2 }));
    else out.push(new TextRun({ ...base, text: part }));
  }
  return out;
}

const body = [];
const front = [];
let tableNo = 0, listNo = 0;
const cellBorder = { style: BorderStyle.SINGLE, size: 4, color: RULE };
const borders = { top: cellBorder, bottom: cellBorder, left: cellBorder, right: cellBorder };

function tableBlock(b) {
  tableNo += 1;
  const widths = b.widths.map(w => Math.round(w * CONTENT));
  widths[widths.length - 1] = CONTENT - widths.slice(0, -1).reduce((s, v) => s + v, 0);
  const cell = (text, i, header) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA }, borders,
    shading: header ? { type: ShadingType.CLEAR, color: 'auto', fill: HEAD_FILL } : undefined,
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    children: [new Paragraph({ spacing: { before: 0, after: 0, line: 240 }, children: runs(text, { size: 18, bold: header, color: INK }) })],
  });
  const out = [
    new Paragraph({ keepNext: true, spacing: { before: 160, after: 80 }, children: [new TextRun({ text: `Table ${tableNo}: `, bold: true, size: 19, color: ACCENT }), ...runs(b.caption, { size: 19, color: ACCENT })] }),
    new Table({
      width: { size: CONTENT, type: WidthType.DXA }, columnWidths: widths,
      rows: [new TableRow({ tableHeader: true, cantSplit: true, children: b.header.map((h, i) => cell(h, i, true)) }),
             ...b.rows.map(r => new TableRow({ cantSplit: true, children: r.map((c, i) => cell(c, i, false)) }))],
    }),
  ];
  out.push(new Paragraph({ spacing: { before: 60, after: 160 }, children: b.note ? runs(b.note, { size: 17, italics: true, color: MUTED }) : [] }));
  return out;
}

function codeBlock(b) {
  const figure = /^Figure/.test(b.caption);
  const out = [new Paragraph({ keepNext: true, spacing: { before: 160, after: 60 }, children: runs(b.caption, { size: 19, bold: true, color: ACCENT }) })];
  b.lines.forEach((line, i) => out.push(new Paragraph({
    keepNext: i < b.lines.length - 1, keepLines: true,
    shading: { type: ShadingType.CLEAR, color: 'auto', fill: 'F3F5F8' },
    spacing: { before: 0, after: 0, line: 228 }, indent: { left: 120, right: 120 },
    children: [new TextRun({ text: line.replace(/ /g, ' ') || ' ', font: MONO, size: figure ? 15 : 16, color: INK })],
  })));
  out.push(new Paragraph({ spacing: { before: 0, after: 160 }, children: [] }));
  return out;
}

let target = front;
for (const b of blocks) {
  switch (b.type) {
    case 'frontmatter': break;
    case 'toc':
      // Styled like a chapter title but not a Heading, so it does not list itself in the contents.
      target.push(new Paragraph({ pageBreakBefore: true, spacing: { before: 0, after: 240 }, children: [new TextRun({ text: 'Contents', font: 'Calibri Light', size: 36, color: ACCENT })] }));
      target.push(new TableOfContents('Contents', { hyperlink: true, headingStyleRange: '1-2' }));
      target.push(new Paragraph({ spacing: { before: 200 }, children: runs('If page numbers are not shown, right-click the table of contents and choose Update Field.', { size: 17, italics: true, color: MUTED }) }));
      target = body;
      break;
    case 'h1': {
      const inBody = target === body;
      target.push(new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: inBody && body.length > 0 || (!inBody && front.length > 0), children: [new TextRun(b.text)] }));
      break;
    }
    case 'h2': target.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(b.text)] })); break;
    case 'h3': target.push(new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(b.text)] })); break;
    // Justification stretches unbreakable URLs and paths into large gaps; keep those paragraphs left-aligned.
    case 'p': target.push(new Paragraph({ alignment: /https?:\/\/|\w\/\w+\//.test(b.text) ? AlignmentType.LEFT : AlignmentType.JUSTIFIED, children: runs(b.text) })); break;
    case 'bullets': b.items.forEach(item => target.push(new Paragraph({ numbering: { reference: 'bullets', level: 0 }, alignment: AlignmentType.LEFT, children: runs(item) }))); break;
    case 'numbers': listNo += 1; b.items.forEach(item => target.push(new Paragraph({ numbering: { reference: 'numbers', level: 0, instance: listNo }, children: runs(item) }))); break;
    case 'table': target.push(...tableBlock(b)); break;
    case 'code': target.push(...codeBlock(b)); break;
    case 'callout': target.push(new Paragraph({
      shading: { type: ShadingType.CLEAR, color: 'auto', fill: NOTE_FILL },
      border: { left: { style: BorderStyle.SINGLE, size: 18, color: 'D69E2E', space: 8 } },
      indent: { left: 160, right: 160 }, spacing: { before: 120, after: 160 }, children: runs(b.text, { italics: true, size: 20 }),
    })); break;
    case 'references': b.items.forEach((ref, i) => target.push(new Paragraph({
      indent: { left: 567, hanging: 567 }, spacing: { after: 100 },
      children: [new TextRun({ text: `[${i + 1}]\t` }), ...runs(ref)], tabStops: [{ type: 'left', position: 567 }],
    }))); break;
    default: throw new Error(`Unknown block ${b.type}`);
  }
}

const cover = [
  new Paragraph({ spacing: { before: 1800, after: 0 }, alignment: AlignmentType.LEFT, children: [new TextRun({ text: 'PROJECT REPORT', bold: true, size: 20, color: MUTED, characterSpacing: 60 })] }),
  new Paragraph({ border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: ACCENT, space: 6 } }, spacing: { before: 200, after: 360 }, children: [new TextRun({ text: meta.title, bold: true, size: 48, color: ACCENT, font: 'Calibri Light' })] }),
  new Paragraph({ spacing: { after: 1200 }, children: [new TextRun({ text: meta.subtitle, size: 26, color: INK })] }),
  new Paragraph({ spacing: { after: 120 }, children: [new TextRun({ text: 'Submitted by', size: 20, color: MUTED })] }),
  ...meta.placeholders.slice(0, 2).map(t => new Paragraph({ spacing: { after: 60 }, children: [new TextRun({ text: t, size: 24, color: 'B45309' })] })),
  new Paragraph({ spacing: { before: 360, after: 120 }, children: [new TextRun({ text: 'In partial fulfilment of the requirements of', size: 20, color: MUTED })] }),
  ...meta.placeholders.slice(2, 4).map(t => new Paragraph({ spacing: { after: 60 }, children: [new TextRun({ text: t, size: 24, color: 'B45309' })] })),
  new Paragraph({ spacing: { before: 360, after: 120 }, children: [new TextRun({ text: 'Under the guidance of', size: 20, color: MUTED })] }),
  new Paragraph({ spacing: { after: 60 }, children: [new TextRun({ text: meta.placeholders[4], size: 24, color: 'B45309' })] }),
  new Paragraph({ spacing: { before: 900 }, children: [new TextRun({ text: meta.date, size: 22, color: INK })] }),
  new Paragraph({ spacing: { before: 120 }, children: [new TextRun({ text: 'Replace the orange placeholders before submission.', size: 16, italics: true, color: MUTED })] }),
];

const pageFooter = new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], size: 18, color: MUTED })] })] });
const doc = new Document({
  creator: 'AegisWeave project', title: meta.title, description: 'AegisWeave ML-NIDS project report',
  styles: {
    default: { document: { run: { font: FONT, size: 22, color: INK }, paragraph: { spacing: { after: 140, line: 288 } } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { font: 'Calibri Light', size: 36, bold: false, color: ACCENT }, paragraph: { spacing: { before: 0, after: 240 }, outlineLevel: 0, keepNext: true } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { font: FONT, size: 27, bold: true, color: ACCENT }, paragraph: { spacing: { before: 320, after: 120 }, outlineLevel: 1, keepNext: true } },
      { id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { font: FONT, size: 23, bold: true, color: INK }, paragraph: { spacing: { before: 220, after: 80 }, outlineLevel: 2, keepNext: true } },
    ],
  },
  numbering: { config: [
    { reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 300 }, spacing: { after: 80 } } } }] },
    { reference: 'numbers', levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 360 }, spacing: { after: 80 } } } }] },
  ] },
  sections: [
    { properties: { page: { size: PAGE, margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN } } }, children: cover },
    { properties: { page: { size: PAGE, margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN }, pageNumbers: { start: 1, formatType: NumberFormat.LOWER_ROMAN } } },
      footers: { default: pageFooter }, children: front },
    { properties: { page: { size: PAGE, margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN }, pageNumbers: { start: 1, formatType: NumberFormat.DECIMAL } } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: RULE, space: 4 } }, children: [new TextRun({ text: 'AegisWeave — ML-first network intrusion detection', size: 16, color: MUTED })] })] }) },
      footers: { default: pageFooter }, children: body },
  ],
});

Packer.toBuffer(doc).then(buffer => { fs.writeFileSync(OUT, buffer); console.log(`wrote ${OUT} (${buffer.length} bytes, ${tableNo} tables)`); });
