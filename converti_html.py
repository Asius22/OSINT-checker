import re
import html
import pyperclip

def convert_bold(text: str) -> str:
    """
    Converte **testo** in <strong>testo</strong>.
    """
    return re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)


def convert_markdown_to_html(input_file: str, output_file: str) -> None:
    html_lines = []
    inside_code_block = False
    code_buffer = []

    with open(input_file, "r", encoding="utf-8") as infile:
        for line in infile:
            line = line.rstrip("\n")
            if len(line)<= 0:
                continue
            
            if line.startswith("-"):
                text = line.replace("-", "").strip()
                html_lines.append(f"<ul><li>{text}</li></ul>")
                continue
                
            
            if line.strip() == "```jsx":
                inside_code_block = True
                code_buffer = []
                continue

            if inside_code_block and line.strip() == "```":
                escaped_code_lines = [
                    html.escape(code_line) + "<br/>"
                    for code_line in code_buffer
                ]

                escaped_code = "\n".join(escaped_code_lines)
                html_lines.append(f"<pre><code>{escaped_code}</code></pre>")

                inside_code_block = False
                continue

            if inside_code_block:
                code_buffer.append(line)
                continue

            match = re.match(r"^(#{1,3})\s*(.*)", line)

            if match:
                level = len(match.group(1))
                text = match.group(2).strip()
                text = convert_bold(html.escape(text))
                html_lines.append(f"<h{level}>{text}</h{level}>")
            else:
                text = convert_bold(html.escape(line))
                text = text.replace("`", "")
                html_lines.append(f"<p>{text}</p>")

    with open(output_file, "w", encoding="utf-8") as outfile:
        text = "\n".join(html_lines)
        outfile.write(text)
        pyperclip.copy(text)

def main():

    convert_markdown_to_html('commento.md', 'output')


if __name__ == "__main__":
    main()