"""
Generador de configuración candidata (Digital Twin).

Aplica sintácticamente los comandos de un plan de remediación (Plan A / Plan B) sobre la
configuración sanitizada original para producir una *configuración candidata* que luego
se carga en Batfish como segundo snapshot (compareFilters).

Soporta el subconjunto de sintaxis usado por los planes: contextos `ip access-list`,
`interface`, `line vty` y `access-list` de ASA, con inserción por secuencia (`N regla`)
y borrado (`no N` / `no <comando>`).
"""
import re
from typing import List, Tuple

_IGNORED = {"configure terminal", "conf t", "end", "exit", "write memory", "wr", "copy running-config startup-config"}
_CONTEXT_RE = re.compile(
    r"^(ip\s+access-list\s+(?:extended|standard)\s+\S+|interface\s+\S+|line\s+vty\s+.*|object-group\s+.*|object\s+.*)$",
    re.IGNORECASE,
)
_SEQ_RE = re.compile(r"^(\d+)\s+(.*)$")


def _split_blocks(lines: List[str]) -> List[Tuple[str, List[str]]]:
    """Divide la config en bloques (cabecera, hijos). Las líneas sueltas son bloques sin hijos."""
    blocks: List[Tuple[str, List[str]]] = []
    for line in lines:
        if line.startswith((" ", "\t")) and blocks:
            blocks[-1][1].append(line)
        else:
            blocks.append((line, []))
    return blocks


def _seq_of(child: str) -> int:
    m = _SEQ_RE.match(child.strip())
    return int(m.group(1)) if m else -1


def apply_commands(config_text: str, commands: List[str]) -> str:
    """Devuelve la configuración candidata resultante de aplicar `commands` a `config_text`."""
    blocks = _split_blocks(config_text.splitlines())
    trailing_end = None
    if blocks and blocks[-1][0].strip().lower() == "end":
        trailing_end = blocks.pop()
    ctx: int = -1  # índice del bloque en contexto actual

    def find_block(header: str) -> int:
        for i, (h, _) in enumerate(blocks):
            if h.strip().lower() == header.strip().lower():
                return i
        return -1

    for raw in commands:
        cmd = raw.strip()
        if not cmd or cmd.startswith("!") or cmd.lower() in _IGNORED:
            if cmd.lower() in {"end", "exit"}:
                ctx = -1
            continue

        if _CONTEXT_RE.match(cmd):
            idx = find_block(cmd)
            if idx == -1:
                blocks.append((cmd, []))
                idx = len(blocks) - 1
            ctx = idx
            continue

        if ctx == -1:
            # Comando global: 'no <línea>' elimina, otro se agrega al final
            if cmd.lower().startswith("no "):
                target = cmd[3:].strip().lower()
                blocks = [b for b in blocks if b[0].strip().lower() != target]
            else:
                blocks.append((cmd, []))
            continue

        header, children = blocks[ctx]
        negate = cmd.lower().startswith("no ")
        body = cmd[3:].strip() if negate else cmd

        if negate:
            seq_m = re.fullmatch(r"\d+", body)
            if seq_m:
                children[:] = [c for c in children if _seq_of(c) != int(body)]
            else:
                children[:] = [c for c in children if c.strip().lower() != body.lower()]
            continue

        seq_m = _SEQ_RE.match(body)
        new_line = f" {body}"
        if seq_m and header.lower().startswith("ip access-list"):
            seq = int(seq_m.group(1))
            children[:] = [c for c in children if _seq_of(c) != seq]
            pos = len(children)
            for i, c in enumerate(children):
                s = _seq_of(c)
                if s != -1 and s > seq:
                    pos = i
                    break
            children.insert(pos, new_line)
        elif new_line not in children:
            children.append(new_line)

    if trailing_end is not None:
        blocks.append(trailing_end)
    out: List[str] = []
    for header, children in blocks:
        out.append(header)
        out.extend(children)
    return "\n".join(out) + "\n"
