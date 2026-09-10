"""Pure, verified IPv4 subnet and quiz logic."""
from dataclasses import dataclass
import ipaddress
import random


@dataclass(frozen=True)
class QuizQuestion:
    identifier: int
    question_type: str
    question_text: str
    correct_answer: str

# Fixed source facts supplied by the project owner. No questions are generated
# from live data; each row is a reviewed question-answer record.
_RAW_BANK = '''
1|subnet_membership|10.0.4.224/21|10.0.0.0
2|broadcast_address|172.16.32.0/25|172.16.32.127
3|usable_hosts|/23|510
4|broadcast_address|192.168.50.0/25|192.168.50.127
5|cidr_to_mask|/18|255.255.192.0
6|subnet_membership|192.168.10.6/26|192.168.10.0
7|broadcast_address|10.20.30.0/27|10.20.30.31
8|cidr_to_mask|/23|255.255.254.0
9|cidr_to_mask|/17|255.255.128.0
10|subnet_membership|192.168.48.94/21|192.168.48.0
11|subnet_membership|172.20.11.140/23|172.20.10.0
12|cidr_to_mask|/20|255.255.240.0
13|usable_hosts|/17|32766
14|usable_hosts|/22|1022
15|cidr_to_mask|/22|255.255.252.0
16|subnet_membership|10.0.0.21/27|10.0.0.0
17|cidr_to_mask|/26|255.255.255.192
18|usable_hosts|/27|30
19|broadcast_address|172.20.10.0/28|172.20.10.15
20|broadcast_address|192.168.1.0/25|192.168.1.127
21|broadcast_address|172.31.100.0/23|172.31.101.255
22|subnet_membership|172.20.10.74/25|172.20.10.0
23|broadcast_address|192.168.100.0/27|192.168.100.31
24|cidr_to_mask|/28|255.255.255.240
25|cidr_to_mask|/16|255.255.0.0
26|usable_hosts|/21|2046
27|usable_hosts|/29|6
28|usable_hosts|/19|8190
29|broadcast_address|10.20.30.0/24|10.20.30.255
30|broadcast_address|192.168.10.0/23|192.168.11.255
31|usable_hosts|/20|4094
32|cidr_to_mask|/25|255.255.255.128
33|cidr_to_mask|/30|255.255.255.252
34|cidr_to_mask|/27|255.255.255.224
35|cidr_to_mask|/19|255.255.224.0
36|subnet_membership|10.0.6.216/21|10.0.0.0
37|subnet_membership|192.168.51.11/21|192.168.48.0
38|broadcast_address|192.168.100.0/24|192.168.100.255
39|usable_hosts|/16|65534
40|usable_hosts|/25|126
41|usable_hosts|/24|254
42|broadcast_address|192.168.0.0/23|192.168.1.255
43|subnet_membership|172.16.0.213/24|172.16.0.0
44|subnet_membership|172.20.10.35/22|172.20.8.0
45|usable_hosts|/18|16382
46|subnet_membership|10.10.1.124/22|10.10.0.0
47|subnet_membership|10.10.1.88/23|10.10.0.0
48|broadcast_address|192.168.50.0/27|192.168.50.31
49|usable_hosts|/28|14
50|cidr_to_mask|/24|255.255.255.0
51|first_usable_host|192.168.10.64/26|192.168.10.65
52|last_usable_host|192.168.10.64/26|192.168.10.126
53|first_usable_host|10.0.0.0/24|10.0.0.1
54|last_usable_host|10.0.0.0/24|10.0.0.254
55|first_usable_host|172.16.8.128/25|172.16.8.129
56|last_usable_host|172.16.8.128/25|172.16.8.254
57|first_usable_host|192.0.2.32/27|192.0.2.33
58|last_usable_host|192.0.2.32/27|192.0.2.62
59|wildcard_mask|/24|0.0.0.255
60|wildcard_mask|/25|0.0.0.127
61|wildcard_mask|/26|0.0.0.63
62|wildcard_mask|/27|0.0.0.31
63|wildcard_mask|/28|0.0.0.15
64|wildcard_mask|/16|0.0.255.255
65|wildcard_mask|/22|0.0.3.255
66|wildcard_mask|/30|0.0.0.3
67|subnet_membership|192.168.100.190/26|192.168.100.128
68|subnet_membership|10.4.15.222/20|10.4.0.0
69|subnet_membership|172.18.35.17/22|172.18.32.0
70|broadcast_address|192.168.200.64/26|192.168.200.127
71|broadcast_address|10.1.2.0/22|10.1.3.255
72|broadcast_address|172.16.12.0/21|172.16.15.255
73|usable_hosts|/26|62
74|usable_hosts|/30|2
75|cidr_to_mask|/29|255.255.255.248
76|cidr_to_mask|/21|255.255.248.0
77|first_usable_host|198.51.100.128/26|198.51.100.129
78|first_usable_host|10.1.0.0/23|10.1.0.1
79|first_usable_host|172.16.16.0/20|172.16.16.1
80|last_usable_host|198.51.100.128/26|198.51.100.190
81|last_usable_host|10.1.0.0/23|10.1.1.254
82|last_usable_host|172.16.16.0/20|172.16.31.254
83|last_usable_host|203.0.113.240/28|203.0.113.254
84|wildcard_mask|/23|0.0.1.255
85|wildcard_mask|/21|0.0.7.255
86|wildcard_mask|/20|0.0.15.255
87|wildcard_mask|/19|0.0.31.255
88|wildcard_mask|/18|0.0.63.255
89|wildcard_mask|/17|0.0.127.255
90|wildcard_mask|/8|0.255.255.255
'''

def _wording(kind, value):
    if kind == 'subnet_membership': return f'What is the network (subnet) address for the host {value}?'
    if kind == 'broadcast_address': return f'What is the broadcast address for the network {value}?'
    if kind == 'usable_hosts': return f'How many usable host addresses are available in a {value} network?'
    if kind == 'first_usable_host': return f'What is the first usable host address in the network {value}?'
    if kind == 'last_usable_host': return f'What is the last usable host address in the network {value}?'
    if kind == 'wildcard_mask': return f'What is the Cisco wildcard mask for a {value} network?'
    return f'What is the decimal subnet mask for a {value} network?'

QUIZ_BANK = tuple(QuizQuestion(int(i), kind, _wording(kind, value), answer) for i, kind, value, answer in (line.split('|') for line in _RAW_BANK.splitlines() if line))

def cidr_to_mask(prefix):
    prefix=int(str(prefix).lstrip('/'))
    if not 0 <= prefix <= 32: raise ValueError('CIDR prefix must be an integer from 0 to 32.')
    return str(ipaddress.IPv4Network(f'0.0.0.0/{prefix}').netmask)

def quiz_choices(answer, rng=None):
    """Build four distinct multiple-choice options that include the correct answer.

    Alternatives are derived from the answer itself (neighbouring values for
    counts, octet variations for addresses) so every option stays plausible.
    The last-octet neighbour wraps around (0 -> 255) so answers ending in .0
    never collide with the correct answer.
    """
    if answer.isdigit():
        value = int(answer)
        candidates = [answer, str(value + 1), str(max(0, value - 1)), str(value * 2)]
    else:
        parts = [int(part) for part in answer.split(".")]
        candidates = [
            answer,
            ".".join(str((part + 1) % 256) if index == 3 else str(part) for index, part in enumerate(parts)),
            ".".join(str((part - 1) % 256) if index == 3 else str(part) for index, part in enumerate(parts)),
            ".".join(str((part + 1) % 256) if index == 2 else str(part) for index, part in enumerate(parts)),
        ]
    values = list(dict.fromkeys(candidates))
    fill = 0
    while len(values) < 4:
        candidate = str(fill)  # Safety net; unreachable for valid IPv4 answers.
        if candidate not in values:
            values.append(candidate)
        fill += 1
    (rng or random).shuffle(values)
    return values

def verify_quiz_bank():
    """Independently verify every supplied answer using IPv4 arithmetic."""
    if len(QUIZ_BANK) != 90 or {q.identifier for q in QUIZ_BANK} != set(range(1,91)): raise ValueError('Quiz bank must contain identifiers 1 through 90.')
    for q in QUIZ_BANK:
        if q.question_type == 'subnet_membership': expected=str(ipaddress.IPv4Network(q.question_text.split('host ')[1][:-1], strict=False).network_address)
        elif q.question_type == 'broadcast_address': expected=str(ipaddress.IPv4Network(q.question_text.split('network ')[1][:-1], strict=False).broadcast_address)
        elif q.question_type == 'usable_hosts':
            prefix=int(q.question_text.split(' a /')[1].split()[0]); expected=str((1 << (32-prefix))-2)
        elif q.question_type == 'first_usable_host': expected=str(ipaddress.IPv4Network(q.question_text.split('network ')[1][:-1], strict=False).network_address + 1)
        elif q.question_type == 'last_usable_host': expected=str(ipaddress.IPv4Network(q.question_text.split('network ')[1][:-1], strict=False).broadcast_address - 1)
        elif q.question_type == 'wildcard_mask':
            prefix=int(q.question_text.split(' a /')[1].split()[0]); expected=str(ipaddress.IPv4Address((1 << (32-prefix))-1))
        else: expected=cidr_to_mask(q.question_text.split(' a /')[1].split()[0])
        if q.correct_answer != expected: raise ValueError(f'Question {q.identifier} has an invalid answer.')

class QuizSession:
    def __init__(self, rng=None):
        verify_quiz_bank(); self.questions=list(QUIZ_BANK); (rng or random.Random()).shuffle(self.questions); self.position=0
    @property
    def complete(self): return self.position == len(self.questions)
    @property
    def current(self):
        if self.complete: raise IndexError('The quiz session is complete.')
        return self.questions[self.position]
    def submit(self, answer):
        correct=answer.strip()==self.current.correct_answer; self.position+=1; return correct

def allocate_vlsm(base_network, requirements):
    """Allocate named positive host requirements largest-first within an IPv4 network."""
    try: base=ipaddress.IPv4Network(base_network, strict=False)
    except ValueError as error: raise ValueError('Enter a valid IPv4 base network, such as 192.168.10.0/24.') from error
    rows=[]
    for name, hosts in requirements:
        if not name.strip() or not isinstance(hosts, int) or isinstance(hosts, bool) or hosts < 1: raise ValueError('Each requirement needs a name and a positive whole host count.')
        rows.append((name.strip(),hosts))
    if not rows: raise ValueError('Add at least one host requirement.')
    if len({name.casefold() for name,_ in rows}) != len(rows): raise ValueError('Each requirement name must be unique.')
    cursor=int(base.network_address); end=int(base.broadcast_address); output=[]
    for name,hosts in sorted(rows,key=lambda row:row[1],reverse=True):
        prefix=next((p for p in range(30,-1,-1) if (1<<(32-p))-2 >= hosts),None)
        if prefix is None: raise ValueError('Requested host count exceeds IPv4 capacity.')
        size=1<<(32-prefix); network=(cursor+size-1)//size*size
        if network+size-1>end: raise ValueError(f'{name} does not fit inside {base.with_prefixlen}. Try a larger base network or reduce host requirements.')
        output.append({'name':name,'requested_hosts':hosts,'network':str(ipaddress.IPv4Address(network)),'cidr':f'/{prefix}','usable_range':f'{ipaddress.IPv4Address(network+1)} – {ipaddress.IPv4Address(network+size-2)}','broadcast':str(ipaddress.IPv4Address(network+size-1))})
        cursor=network+size
    return output


def find_summary_route(networks):
    """Return the smallest supernet that covers all supplied IPv4 networks.

    networks is an iterable of CIDR strings such as
    ['192.168.1.0/24', '192.168.2.0/24', '192.168.3.0/24'].
    Returns a dict {network, prefix, covers, addresses, wasted} where
    wasted is the number of addresses inside the summary block that are not
    part of the original networks (0 for a perfect summarisation).
    """
    parsed = []
    for value in networks:
        try:
            net = ipaddress.IPv4Network(str(value).strip(), strict=False)
        except ValueError:
            raise ValueError(f"'{value}' is not a valid IPv4 network. Use CIDR form, e.g. 192.168.1.0/24.") from None
        parsed.append(net)
    if not parsed:
        raise ValueError("Enter at least one network to summarise.")
    start = min(int(net.network_address) for net in parsed)
    end = max(int(net.broadcast_address) for net in parsed)
    for prefix in range(32, -1, -1):
        size = 1 << (32 - prefix)
        base = (start // size) * size
        if base <= start and base + size - 1 >= end:
            covered_addresses = sum(net.num_addresses for net in parsed)
            return {
                "network": str(ipaddress.IPv4Address(base)),
                "prefix": prefix,
                "covers": len(parsed),
                "addresses": size,
                "wasted": size - covered_addresses,
            }
    raise ValueError("Networks cannot be summarised.")  # pragma: no cover - /0 always succeeds


def aggregate_mastery(entries):
    """Aggregate quiz history into per-category mastery (preview parity).

    entries are recorded attempt dicts with category/score/total. Categories
    labelled 'Mixed topics' are excluded because they mix every topic.
    Returns a list of dicts sorted by attempts descending:
    [{category, attempts, correct, total, percentage}]
    """
    grouped = {}
    for entry in entries:
        category = entry.get("category")
        if not category or category == "Mixed topics":
            continue
        item = grouped.setdefault(category, {"attempts": 0, "correct": 0, "total": 0})
        item["attempts"] += 1
        item["correct"] += int(entry.get("score") or 0)
        item["total"] += int(entry.get("total") or 0)
    output = []
    for category, item in grouped.items():
        percentage = round(item["correct"] / item["total"] * 100) if item["total"] else 0
        output.append({**item, "category": category, "percentage": percentage})
    return sorted(output, key=lambda row: row["attempts"], reverse=True)
