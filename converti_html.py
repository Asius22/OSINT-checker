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

    inside_list = False

    with open(input_file, "r", encoding="utf-8") as infile:
        for line in infile:
            line = line.rstrip("\n")

            # CODE BLOCK
            if line.strip() == "```jsx" or line.strip() == "```":
                # Se c'era una lista aperta, la chiudo
                if inside_list:
                    html_lines.append("</ul>")
                    inside_list = False

                inside_code_block = True
                code_buffer = []
                continue

            if inside_code_block and line.strip() == "```":
                escaped_code_lines = [
                    html.escape(code_line) + "<br/>"
                    for code_line in code_buffer
                ]

                escaped_code = "\n".join(escaped_code_lines)

                html_lines.append(
                    f"<pre><code>{escaped_code}</code></pre>"
                )

                inside_code_block = False
                continue

            if inside_code_block:
                code_buffer.append(line)
                continue

            # RIGA VUOTA
            if len(line.strip()) == 0:
                if inside_list:
                    html_lines.append("</ul>")
                    inside_list = False

                continue

            # LISTA
            if line.strip().startswith("-"):
                text = line.strip()[1:].strip()

                text = convert_bold(html.escape(text))
                text = text.replace("`", "")

                # Apro <ul> soltanto al primo elemento
                if not inside_list:
                    html_lines.append("<ul>")
                    inside_list = True

                html_lines.append(f"<li>{text}</li>")
                continue

            # Se la riga attuale non è una lista,
            # chiudo l'eventuale lista precedente
            if inside_list:
                html_lines.append("</ul>")
                inside_list = False

            # HEADINGS
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

    # Nel caso il file finisca mentre siamo ancora dentro una lista
    if inside_list:
        html_lines.append("</ul>")

    with open(output_file, "w", encoding="utf-8") as outfile:
        text = "\n".join(html_lines)

        outfile.write(text)
        pyperclip.copy(text)


def main():
    convert_markdown_to_html("commento.md", "output")


if __name__ == "__main__":
    main()