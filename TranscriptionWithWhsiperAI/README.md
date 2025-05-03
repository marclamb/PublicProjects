# 🎙️ TranscriptionWithWhisperAI

A simple Python script that uses [OpenAI's Whisper](https://github.com/openai/whisper) to transcribe audio files into `.txt` files using a file picker.

---

## 📦 Features

- GUI-based audio file selection
- Transcribes audio to text using Whisper
- Saves the result in the same folder as the input file
- FFmpeg dependency check with popup alerts

---

## 🛠️ Requirements

- Python 3.8+
- [Whisper](https://github.com/openai/whisper)
- [FFmpeg](https://ffmpeg.org/)
- Tkinter (comes with most Python installs)

---

## 🧩 Installation

### 1. **Install FFmpeg**

#### ➤ Download

- Go to: [https://ffmpeg.org/download.html](https://ffmpeg.org/download.html?utm_source=chatgpt.com)
- Click the **Windows logo**
- Download the **`ffmpeg-git-full.7z`** version

#### ➤ Extract

- Use [7-Zip](https://www.7-zip.org/) or similar
- Extract to `C:\ffmpeg`

#### ➤ Add to PATH

1. Open Start and search **Environment Variables**
2. Click **"Edit the system environment variables"**
3. In **System Properties**, click **Environment Variables**
4. Under **System Variables**, find `Path` → click **Edit**
5. Click **New** and add:

   C:\ffmpeg\bin
6. Click **OK** to save

#### ➤ Verify

Open **Command Prompt** and run: **ffmpeg -version**

You should see version info.

### 2. Install Whisper
➤ Install Python 3.8+
Download: https://www.python.org/downloads/

➤ Install Whisper via pip: pip install git+https://github.com/openai/whisper.git

## 🚀 Usage
python whisper_gui_transcribe.py

1. A pop-up will let you choose an audio file (.wav, .mp3, .m4a, etc.)
2. The script will transcribe it and save a .txt file in the same folder

💡 Example: Input File -> Output File

Intro.wav -> Intro.txt

Meeting.mp3	-> Meeting.txt

## 📌 Notes
- If FFmpeg is not found, the script will alert you.
- Supported formats depend on FFmpeg (.mp3, .wav, .m4a, etc.)

## 🧠 License
MIT License





