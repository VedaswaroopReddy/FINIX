"""
parser.py: 3-Stage Lexical Analysis, Shunting-Yard Postfix Conversion, and AST Construction.
Provides exact error pinpointing, explicit concatenation (·), and formal AST serialization.
"""

from typing import List, Optional, Set, Tuple
from enum import Enum, auto

CONCAT_OP = '·'
UNSUPPORTED_OPERATORS: Set[str] = set()

PRINTABLE_ASCII = frozenset(chr(i) for i in range(32, 127)) | {'\t', '\r', '\n'}
DIGITS = frozenset("0123456789")
WORD_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
WHITESPACE = frozenset({' ', '\t', '\r', '\n'})

SHORTHANDS = {
    'd': (DIGITS, r"\d"),
    'D': (PRINTABLE_ASCII - DIGITS, r"\D"),
    'w': (WORD_CHARS, r"\w"),
    'W': (PRINTABLE_ASCII - WORD_CHARS, r"\W"),
    's': (WHITESPACE, r"\s"),
    'S': (PRINTABLE_ASCII - WHITESPACE, r"\S"),
}


class TokenType(Enum):
    CHAR = auto()
    ANY = auto()
    CHAR_CLASS = auto()
    STAR = auto()
    PLUS = auto()
    OPTIONAL = auto()
    UNION = auto()
    CONCAT = auto()
    LPAREN = auto()
    RPAREN = auto()


class Token:
    """Represents a lexical token with exact source position tracking."""
    def __init__(self, token_type: TokenType, value: str, pos: int = 0,
                 escaped: bool = False, charset: Optional[frozenset] = None):
        self.type = token_type
        self.value = value
        self.pos = pos
        self.escaped = escaped
        self.charset = charset

    def __repr__(self) -> str:
        esc = " [esc]" if self.escaped else ""
        return f"Token({self.type.name}, '{self.value}'{esc}, pos={self.pos})"

    def __eq__(self, other) -> bool:
        if not isinstance(other, Token):
            return False
        return self.type == other.type and self.value == other.value


PRECEDENCE = {
    TokenType.STAR: 3,
    TokenType.PLUS: 3,
    TokenType.OPTIONAL: 3,
    TokenType.CONCAT: 2,
    TokenType.UNION: 1,
}


def _parse_character_class(regex_str: str, start_idx: int) -> Tuple[Token, int]:
    """
    Parses a character class [...] starting at start_idx ('[').
    Returns (Token, next_idx).
    """
    n = len(regex_str)
    i = start_idx + 1
    is_negated = False

    if i < n and regex_str[i] == '^':
        is_negated = True
        i += 1

    if i >= n:
        raise ValueError(f"Syntax Error: Unclosed character class '[' at position {start_idx}")

    if regex_str[i] == ']':
        raise ValueError(f"Syntax Error: Empty character class at position {start_idx}")

    chars: Set[str] = set()

    while i < n:
        if regex_str[i] == ']':
            final_set = (PRINTABLE_ASCII - chars) if is_negated else frozenset(chars)
            raw_val = regex_str[start_idx : i + 1]
            return Token(TokenType.CHAR_CLASS, raw_val, pos=start_idx, charset=final_set), i + 1

        # Check for escape sequence inside character class
        if regex_str[i] == '\\':
            if i + 1 >= n:
                raise ValueError(f"Syntax Error: Trailing backslash in character class at position {i}")
            esc = regex_str[i + 1]
            if esc == 'x' and i + 3 < n:
                try:
                    code = int(regex_str[i + 2 : i + 4], 16)
                    curr_char = chr(code)
                    i += 4
                except ValueError:
                    curr_char = esc
                    i += 2
            elif esc in SHORTHANDS:
                chars.update(SHORTHANDS[esc][0])
                i += 2
                continue
            else:
                curr_char = esc
                i += 2
        else:
            curr_char = regex_str[i]
            i += 1

        # Check if this character is the start of a range (e.g., 'a-z')
        # '-' is literal if it's the last character before ']'
        if i < n and regex_str[i] == '-' and (i + 1 < n and regex_str[i + 1] != ']'):
            i += 1  # Consume '-'
            if regex_str[i] == '\\':
                if i + 1 >= n:
                    raise ValueError(f"Syntax Error: Trailing backslash in character class at position {i}")
                esc2 = regex_str[i + 1]
                if esc2 == 'x' and i + 3 < n:
                    try:
                        code2 = int(regex_str[i + 2 : i + 4], 16)
                        end_char = chr(code2)
                        i += 4
                    except ValueError:
                        end_char = esc2
                        i += 2
                elif esc2 in SHORTHANDS:
                    raise ValueError(f"Syntax Error: Shorthand escape '\\{esc2}' cannot be range boundary at position {i}")
                else:
                    end_char = esc2
                    i += 2
            else:
                end_char = regex_str[i]
                i += 1

            if ord(curr_char) > ord(end_char):
                raise ValueError(
                    f"Syntax Error: Invalid range '{curr_char}-{end_char}' at position {i - 3}: range values out of order"
                )

            for code in range(ord(curr_char), ord(end_char) + 1):
                chars.add(chr(code))
        else:
            chars.add(curr_char)

    raise ValueError(f"Syntax Error: Unclosed character class '[' at position {start_idx}")


def tokenize(regex_str: str) -> List[Token]:
    """
    Tokenizes raw regex string into tokens with position tracking.
    Handles escape sequences (\\., \\/, \\*, \\+, \\?, \\d, \\w, \\s), character classes [...],
    quantifiers (+, ?, *), and strict error detection.
    """
    if not regex_str:
        return []

    working = regex_str
    if working.startswith('^'):
        working = working[1:]
    if working.endswith('$') and not working.endswith(r'\$'):
        working = working[:-1]

    if not working:
        raise ValueError("Syntax Error: Expression contains only anchors with no pattern body")

    tokens: List[Token] = []
    i = 0
    n = len(working)
    paren_depth = 0

    while i < n:
        char = working[i]

        if char == '\\':
            if i + 1 < n:
                esc = working[i + 1]
                if esc == 'x' and i + 3 < n:
                    try:
                        code = int(working[i + 2 : i + 4], 16)
                        tokens.append(Token(TokenType.CHAR, chr(code), pos=i, escaped=True))
                        i += 4
                        continue
                    except ValueError:
                        pass
                if esc in SHORTHANDS:
                    cset, disp = SHORTHANDS[esc]
                    tokens.append(Token(TokenType.CHAR_CLASS, disp, pos=i, charset=cset))
                else:
                    tokens.append(Token(TokenType.CHAR, esc, pos=i, escaped=True))
                i += 2
            else:
                raise ValueError(f"Syntax Error: Trailing backslash at position {i}")
        elif char == '[':
            tok, next_i = _parse_character_class(working, i)
            tokens.append(tok)
            i = next_i
        elif char == '(':
            tokens.append(Token(TokenType.LPAREN, '(', pos=i))
            paren_depth += 1
            i += 1
        elif char == ')':
            if paren_depth <= 0:
                raise ValueError(f"Syntax Error: Unmatched closing parenthesis ')' at position {i}")
            tokens.append(Token(TokenType.RPAREN, ')', pos=i))
            paren_depth -= 1
            i += 1
        elif char == '*':
            tokens.append(Token(TokenType.STAR, '*', pos=i))
            i += 1
        elif char == '+':
            tokens.append(Token(TokenType.PLUS, '+', pos=i))
            i += 1
        elif char == '?':
            tokens.append(Token(TokenType.OPTIONAL, '?', pos=i))
            i += 1
        elif char == '|':
            tokens.append(Token(TokenType.UNION, '|', pos=i))
            i += 1
        elif char == '.':
            tokens.append(Token(TokenType.ANY, '.', pos=i))
            i += 1
        elif char == '{':
            close_idx = working.find('}', i)
            if close_idx == -1:
                raise ValueError(f"Syntax Error: Unclosed quantifier '{{' at position {i}")
            body = working[i + 1 : close_idx].strip()
            parts = body.split(',')
            if len(parts) > 2 or not parts[0].strip().isdigit():
                raise ValueError(f"Syntax Error: Invalid quantifier '{{{body}}}' at position {i}")
            min_val = int(parts[0].strip())
            if min_val < 0 or min_val > 64:
                raise ValueError(f"Syntax Error: Quantifier lower bound {min_val} out of range [0, 64]")
            if len(parts) == 2:
                p2 = parts[1].strip()
                if p2 == '':
                    max_val = None
                elif p2.isdigit():
                    max_val = int(p2)
                    if max_val < min_val or max_val > 64:
                        raise ValueError(f"Syntax Error: Quantifier upper bound {max_val} must satisfy {min_val} <= m <= 64")
                else:
                    raise ValueError(f"Syntax Error: Invalid quantifier '{{{body}}}' at position {i}")
            else:
                max_val = min_val

            if not tokens:
                raise ValueError(f"Syntax Error: Quantifier '{{{body}}}' at position {i} has no preceding operand")

            prev_tok = tokens[-1]
            if prev_tok.type in {TokenType.STAR, TokenType.PLUS, TokenType.OPTIONAL, TokenType.UNION, TokenType.LPAREN}:
                raise ValueError(f"Syntax Error: Quantifier '{{{body}}}' cannot follow '{prev_tok.value}'")

            if prev_tok.type == TokenType.RPAREN:
                depth = 1
                j = len(tokens) - 2
                while j >= 0 and depth > 0:
                    if tokens[j].type == TokenType.RPAREN:
                        depth += 1
                    elif tokens[j].type == TokenType.LPAREN:
                        depth -= 1
                    j -= 1
                atom = tokens[j + 1 :]
                del tokens[j + 1 :]
            else:
                atom = [tokens.pop()]

            wrap = len(atom) > 1 and not (atom[0].type == TokenType.LPAREN and atom[-1].type == TokenType.RPAREN)
            wrapped_atom = [Token(TokenType.LPAREN, '(', i)] + atom + [Token(TokenType.RPAREN, ')', i)] if wrap else atom

            for _ in range(min_val):
                tokens.extend([Token(t.type, t.value, pos=t.pos, escaped=t.escaped, charset=t.charset) for t in wrapped_atom])

            if max_val is None:
                tokens.extend([Token(TokenType.LPAREN, '(', i)] + wrapped_atom + [Token(TokenType.RPAREN, ')', i), Token(TokenType.STAR, '*', i)])
            else:
                opt_count = max_val - min_val
                for _ in range(opt_count):
                    tokens.extend([Token(TokenType.LPAREN, '(', i)] + wrapped_atom + [Token(TokenType.RPAREN, ')', i), Token(TokenType.OPTIONAL, '?', i)])

            i = close_idx + 1
        elif char == '}':
            raise ValueError(f"Syntax Error: Unmatched closing brace '}}' at position {i}")
        elif char in UNSUPPORTED_OPERATORS:
            raise ValueError(
                f"Scope Limitation: Operator '{char}' at position {i} is not supported."
            )
        else:
            tokens.append(Token(TokenType.CHAR, char, pos=i))
            i += 1

    if paren_depth > 0:
        raise ValueError(f"Syntax Error: Unmatched opening parenthesis '(' (depth={paren_depth})")

    # Validate consecutive invalid operators
    quantifiers = {TokenType.STAR, TokenType.PLUS, TokenType.OPTIONAL}
    for idx in range(len(tokens) - 1):
        t1, t2 = tokens[idx], tokens[idx + 1]
        if t1.type in quantifiers and t2.type in quantifiers:
            raise ValueError(f"Syntax Error: Repeated quantifier '{t1.value}{t2.value}' at position {t2.pos}")
        if t1.type == TokenType.UNION and t2.type == TokenType.UNION:
            raise ValueError(f"Syntax Error: Consecutive union '||' at position {t2.pos}")
        if t1.type == TokenType.LPAREN and t2.type == TokenType.RPAREN:
            raise ValueError(f"Syntax Error: Empty group '()' at position {t1.pos}")

    if tokens and (tokens[0].type in quantifiers or tokens[0].type == TokenType.UNION):
        raise ValueError(f"Syntax Error: Expression cannot start with operator '{tokens[0].value}'")

    if tokens and tokens[-1].type == TokenType.UNION:
        raise ValueError("Syntax Error: Expression cannot end with trailing union operator '|'")

    return tokens


def insert_explicit_concat(tokens: List[Token]) -> List[Token]:
    """
    Inserts explicit concatenation tokens (·) between adjacent operand fragments.
    Rule: Insert CONCAT between T1 and T2 if:
      T1 in {CHAR, ANY, CHAR_CLASS, STAR, PLUS, OPTIONAL, RPAREN}
      AND
      T2 in {CHAR, ANY, CHAR_CLASS, LPAREN}
    """
    if not tokens:
        return []

    result: List[Token] = []
    can_end = {
        TokenType.CHAR, TokenType.ANY, TokenType.CHAR_CLASS,
        TokenType.STAR, TokenType.PLUS, TokenType.OPTIONAL,
        TokenType.RPAREN
    }
    can_start = {
        TokenType.CHAR, TokenType.ANY, TokenType.CHAR_CLASS,
        TokenType.LPAREN
    }

    for i, token in enumerate(tokens):
        if i > 0:
            prev = tokens[i - 1]
            if prev.type in can_end and token.type in can_start:
                result.append(Token(TokenType.CONCAT, CONCAT_OP, pos=token.pos))
        result.append(token)

    return result


def infix_to_postfix(tokens: List[Token]) -> List[Token]:
    """
    Applies Dijkstra's Shunting-Yard algorithm to produce Postfix (Reverse Polish Notation).
    """
    output: List[Token] = []
    stack: List[Token] = []

    for token in tokens:
        if token.type in {TokenType.CHAR, TokenType.ANY, TokenType.CHAR_CLASS}:
            output.append(token)
        elif token.type == TokenType.LPAREN:
            stack.append(token)
        elif token.type == TokenType.RPAREN:
            while stack and stack[-1].type != TokenType.LPAREN:
                output.append(stack.pop())
            if not stack:
                raise ValueError("Mismatched parentheses: Missing '('")
            stack.pop()  # Pop the LPAREN
        elif token.type in PRECEDENCE:
            curr_prec = PRECEDENCE[token.type]
            while (stack and stack[-1].type in PRECEDENCE and
                   PRECEDENCE[stack[-1].type] >= curr_prec):
                output.append(stack.pop())
            stack.append(token)
        else:
            raise ValueError(f"Unexpected token: {token}")

    while stack:
        top = stack.pop()
        if top.type in {TokenType.LPAREN, TokenType.RPAREN}:
            raise ValueError("Mismatched parentheses")
        output.append(top)

    return output


# ============================================================================
# Abstract Syntax Tree (AST) Model
# ============================================================================

class ASTNode:
    """Base class for Abstract Syntax Tree nodes."""
    def to_string(self) -> str:
        raise NotImplementedError


class LiteralNode(ASTNode):
    def __init__(self, char: str):
        self.char = char

    def to_string(self) -> str:
        return f"literal('{self.char}')"

    def __repr__(self) -> str:
        return self.to_string()


class CharClassNode(ASTNode):
    def __init__(self, display: str, charset: frozenset):
        self.display = display
        self.charset = charset

    def to_string(self) -> str:
        return f"charset('{self.display}')"

    def __repr__(self) -> str:
        return self.to_string()


class WildcardNode(ASTNode):
    def to_string(self) -> str:
        return "any()"

    def __repr__(self) -> str:
        return self.to_string()


class ConcatNode(ASTNode):
    def __init__(self, left: ASTNode, right: ASTNode):
        self.left = left
        self.right = right

    def to_string(self) -> str:
        return f"concat({self.left.to_string()}, {self.right.to_string()})"

    def __repr__(self) -> str:
        return self.to_string()


class UnionNode(ASTNode):
    def __init__(self, left: ASTNode, right: ASTNode):
        self.left = left
        self.right = right

    def to_string(self) -> str:
        return f"union({self.left.to_string()}, {self.right.to_string()})"

    def __repr__(self) -> str:
        return self.to_string()


class StarNode(ASTNode):
    def __init__(self, child: ASTNode):
        self.child = child

    def to_string(self) -> str:
        return f"star({self.child.to_string()})"

    def __repr__(self) -> str:
        return self.to_string()


class PlusNode(ASTNode):
    def __init__(self, child: ASTNode):
        self.child = child

    def to_string(self) -> str:
        return f"plus({self.child.to_string()})"

    def __repr__(self) -> str:
        return self.to_string()


class OptionalNode(ASTNode):
    def __init__(self, child: ASTNode):
        self.child = child

    def to_string(self) -> str:
        return f"optional({self.child.to_string()})"

    def __repr__(self) -> str:
        return self.to_string()


def build_ast(postfix_tokens: List[Token]) -> Optional[ASTNode]:
    """Builds an Abstract Syntax Tree from postfix tokens."""
    if not postfix_tokens:
        return None

    stack: List[ASTNode] = []

    for token in postfix_tokens:
        if token.type == TokenType.CHAR:
            stack.append(LiteralNode(token.value))
        elif token.type == TokenType.ANY:
            stack.append(WildcardNode())
        elif token.type == TokenType.CHAR_CLASS:
            stack.append(CharClassNode(token.value, token.charset or frozenset()))
        elif token.type == TokenType.CONCAT:
            if len(stack) < 2:
                raise ValueError("AST Error: Insufficient operands for ConcatNode")
            right = stack.pop()
            left = stack.pop()
            stack.append(ConcatNode(left, right))
        elif token.type == TokenType.UNION:
            if len(stack) < 2:
                raise ValueError("AST Error: Insufficient operands for UnionNode")
            right = stack.pop()
            left = stack.pop()
            stack.append(UnionNode(left, right))
        elif token.type == TokenType.STAR:
            if len(stack) < 1:
                raise ValueError("AST Error: Insufficient operands for StarNode")
            child = stack.pop()
            stack.append(StarNode(child))
        elif token.type == TokenType.PLUS:
            if len(stack) < 1:
                raise ValueError("AST Error: Insufficient operands for PlusNode")
            child = stack.pop()
            stack.append(PlusNode(child))
        elif token.type == TokenType.OPTIONAL:
            if len(stack) < 1:
                raise ValueError("AST Error: Insufficient operands for OptionalNode")
            child = stack.pop()
            stack.append(OptionalNode(child))

    if len(stack) != 1:
        raise ValueError(f"AST Error: {len(stack)} root nodes on stack after evaluation")

    return stack[0]


def parse_regex(regex_str: str) -> List[Token]:
    """Full parsing pipeline: String -> Tokens -> Explicit Concat -> Postfix Tokens."""
    raw_tokens = tokenize(regex_str)
    concat_tokens = insert_explicit_concat(raw_tokens)
    postfix_tokens = infix_to_postfix(concat_tokens)
    return postfix_tokens


def format_postfix(postfix_tokens: List[Token]) -> str:
    """Formats postfix tokens for visual presentation."""
    return " ".join(t.value for t in postfix_tokens)
