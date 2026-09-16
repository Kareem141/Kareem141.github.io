---
title: The Extension Lie
date: 2026-09-16 12:05:33 +0200
categories: [Other]
tags: [mime, file-type, magic-bytes]
description: How a script disguised as a PDF slips past your eyes and how to catch it by its bytes instead.
---

Here's something that will feel uncomfortably familiar: you download a file named `invoice.pdf`, double-click it, and your computer opens a PDF viewer. No surprise there. But what if I told you the file isn't actually a PDF at all?

Every operating system, every web server, every email attachment we've all been operating on a comfortable lie. The sticker on the box says one thing. Inside, it's something else entirely.

## Everything Is Just Numbers

---

Let's start from absolute zero. When you open your Documents folder, you see icons, a photo here, a Word document there, a music file over there. It feels like these are fundamentally different *kinds of things*.

They're not.

Every single file on your hard drive, every image, every song, every document, every program is the same thing at the most fundamental level: a long sequence of numbers between 0 and 255. Each of those numbers is called a **byte**. Your 50MB photo, your 2MB Word document, your 5MB MP3 ... they're all just lists of bytes.

Here's a JPEG image opened in a hex editor (a tool that shows you the raw bytes without any interpretation):

![screen.png](assets/img/mime_detec/screen.png)

Every cell there **`FF`, `D8`, `4A`, `6D`,...** is exactly **one byte**, a number from 0 to 255. The `FF` at the very start is the same kind of thing as the `4A` six bytes over. One represents the start of a JPEG. The other represents the letter "J". The software reading the bytes is what decides which it means.

## The Lens of Interpretation

---

So if every file is just bytes, how does your computer know what to show you? The answer is: **the software decides**. Programs act as lenses, applying specific rules to interpret those numbers.

Take four bytes: `48 65 78 21`

- A **text editor** sees `48` and thinks, "That's 'H' in ASCII." `65` is "e." `78` is "x." `21` is "!". Result: you see **"Hex!"**
- An **image viewer** sees the same bytes and tries to interpret them as pixel dimensions, 18,533 pixels wide. It reads the next two as height. The file is too short, so it either crashes or shows a corrupt image.
- If **executed as a program**, the CPU sees `48` as a machine code instruction and tries to run it as software. Usually crashes.

> The bytes never changed. Only the meaning we assigned to them did.
{: .prompt-info }

This is the fundamental trick of computing. Those numbers on the disk are silent. Meaning comes entirely from the lens applied to them.

## The Two Clues We Use 

---

Since bytes alone don't carry their meaning, we've built two systems to guess what a file should be treated as:

### Clue A: The File Extension

It's just a label `.jpg`, `.docx`, `.mp3`, `.exe` appended to the end of the filename. This is a human-readable name for what *should* be inside.

But here's the thing: **anyone can change it.** Rename `malware.exe` to `vacation_photos.jpg.txt` and your operating system will happily try to open it as a text file. Rename it to `invoice.pdf` and it will open in your PDF viewer, which will then choke and crash because those bytes aren't a PDF at all.

> Extensions are like sticky notes on a box. They say what the person who labeled it *claims* is inside. The box doesn't care about the sticky note.
{: .prompt-warning }

### Clue B: Magic Numbers

Because extensions are so trivially forged, real file-detection software ignores them. Instead, it looks at the **first few bytes of the file**, a technique called "magic number" detection.

These are hardcoded fingerprints that file format designers embed at the very beginning of their files. They're the file format equivalent of a wax seal:

| Bytes (hex) | What it means |
|---|---|
| `FF D8 FF` | JPEG image |
| `89 50 4E 47` | PNG image (and `50 4E 47` spells "PNG" in ASCII) |
| `25 50 44 46` | PDF document ("the first four bytes spell `%PDF`") |
| `50 4B 03 04` | ZIP archive (also the hidden format for DOCX, XLSX, APK) |
| `7F 45 4C 46` | ELF executable (Linux programs) |
| `4D 5A` | Windows EXE (starts with "MZ") |

Even if you rename a JPEG from `photo.jpg` to `photo.txt`, your web browser will still display it as an image because it looks at the bytes, sees `FF D8 FF`, and knows: *"this is a JPEG, decode it as a JPEG."*

Magic numbers work because they're embedded in the actual data, not the filename. You can't forge them by renaming a file.

## MIME Types

---

Here's where it gets practical. On the web and in email systems, file types aren't called "image" or "document" ... they're called **MIME types**. MIME stands for *Multipurpose Internet Mail Extension*, which is a fancy name for a simple idea: a standardized string that describes what kind of data something is.

Examples:
- `image/jpeg`
- `image/png`
- `application/pdf`
- `text/plain`
- `text/html`
- `application/vnd.openxmlformats-officedocument.wordprocessingml.document` (yes, that's the real MIME type for `.docx` files, it's a mouthful, but it's specific)

When your browser downloads a file, it asks the server: **"What MIME type did you say this was?"** The server responds with something like `Content-Type: image/jpeg`. Based on that label, the browser decides: show this inline as an image, or download it, or hand it off to a plug-in.

When your email system receives an attachment, it uses the MIME type to decide whether to render a preview or treat it as a download.

MIME types are the lingua franca of "what is this data?" across the internet.

## The Extension vs. Content Problem

---

And here's the collision point: **your file system labels files by extension (`.jpg`), but the web trusts MIME types (`image/jpeg`).** These two systems only agree when someone actually checked the content.

But that doesn't always happen. Here's the uncomfortable reality:

1. A user writes a script (executable program) and saves it as `clean_report.pdf`. The `.pdf` extension suggests a PDF document. The bytes inside are Python code. Nothing actually checked.
2. The user uploads this file to a server. The server sees `.pdf`, assumes it's safe, and stores it.
3. Later, the server sends it back to another user. If it trusts the extension, it says the MIME type is `application/pdf`. The browser opens a PDF viewer. Nothing renders. The file appears "broken."
4. But in a security context, the server is supposed to verify uploads. If it blindly trusted the extension when assigning a MIME type, it just labeled a program file as a PDF. If anything downstream then tries to execute that "PDF" (because of a second, unrelated vulnerability), you have a problem.

This mismatch between what the **extension claims** and what the **content actually is** is a real, persistent gap in how we handle files. And it's exactly what a tool would need to close.

## Containers

---

Here's where it gets interesting. Some file formats are so sophisticated that detecting them from the very beginning isn't enough. You have to look *inside*.

Modern Office documents `.docx`, `.xlsx`, `.pptx` are secretly **ZIP archives**. If you rename `report.docx` to `report.zip`, you can open it and see a folder structure inside, full of XML files. A plain "starts with `50 4B 03 04`" check can tell you "this is a ZIP," but it can't tell you whether it's a Word document, an Excel spreadsheet, or a Java program (JAR files are also ZIP archives under the hood).

To distinguish them, you have to look inside the ZIP and ask: *what internal structure do you have?* A DOCX contains a `word/` folder. An XLSX contains an `xl/` folder. A JAR contains `META-INF/MANIFEST.MF`. The contents of the container tell you what the container actually is.

The same principle applies to older formats. Legacy `.doc`, `.xls`, and `.ppt` files use a completely different container format called **OLE2** (Compound File Binary Format), a tiny filesystem within a file, complete with its own allocation table and directory structure. An MSI installer uses the same container. To tell them apart, you open the container, list its internal "files," and match on what you find.

And modern audio/video formats? **RIFF** (used by WAV and AVI), **EBML** (used by MKV and WebM) same story. The outer wrapper tells you the container family. The inner structure tells you the specific type.

Detection by "first few bytes" is the starting point. But the real work, the accurate work is looking past the outer shell and asking what's actually structured inside.

## Why This Matters Beyond Curiosity

---

This isn't just an interesting quirk of how file systems work. It's a real, practical concern at the intersection of **security, data integrity, and correctness**.

**Security:** An attacker who can upload files to a server often does it by renaming `payload.exe` to `payload.png`. If the server's only validation is "does it end in `.png`?", the attacker wins. If the server actually inspects the bytes and detects "this is an executable, not an image," the attack fails.

**Data integrity:** Over time, files get moved, copied, converted, and renamed. A file's extension can drift from what it actually contains. A tool that trusts extensions will faithfully propagate that drift. A tool that trusts bytes will report the truth.

**API correctness:** When a web endpoint accepts a file upload and reports back "I saved your image/png," it should mean the bytes are genuinely a PNG image not that the user called it `.png` and nobody checked.

The core problem is simple: **we have two labels for files: the extension and the content and they're supposed to agree, but nothing enforces that they do.**

## A Detective for Byte Truth

---

This is the gap that led to building a detection tool. The tool's job is straightforward in concept: given a file, look at its actual bytes, determine its real MIME type using magic numbers and container inspection, and then compare that against what the file's extension claims.

If the bytes say `image/png` but the extension says `.jpg` mismatch detected. If the bytes say `application/x-dosexec` (a Windows program) but the extension says `.pdf` mismatch detected. If the bytes say nothing recognizable at all undetermined, flagged for review.

The tool layers its detection: it starts with hard magic-byte signatures (the certain cases), falls back to container structure analysis (the clever cases), and only as a last resort uses heuristics for plain text files (the uncertain cases). Optional cross-checks against established libraries give you a second opinion when they're available.

It's a tool that trusts the bytes over the label. Because in a world where a single rename can turn malware into a "document," that's the only safe default.


*The bytes never lie. They're just numbers, waiting for someone to apply the right lens.*