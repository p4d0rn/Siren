from bs4 import BeautifulSoup, Comment


def parse_tat(html: str) -> list:
    tokenizer = []
    soup = BeautifulSoup(html, 'html.parser')
    for tag_name in {tag.name for tag in soup.find_all()}:
        for tag in soup.find_all(tag_name):
            tokenizer.append({
                "tag": tag_name,
                "attributes": tag.attrs,
                "text": tag.string if tag.string else ''
            })
    comments = soup.find_all(text=lambda text: isinstance(text, Comment))
    if comments:
        tokenizer.append({
            "comment": list(comments)
        })
    return tokenizer


def pos_check(flag: str, html: str) -> list:
    """
    get potential injection position
    """
    pos = []
    if tokens := parse_tat(html):
        for token in tokens[:-1]:
            if flag in token['tag']:
                pos.append({
                    'pos': 'tag',
                    'detail': token
                })
            for k, v in token['attributes'].items():
                name = None
                if flag in k:
                    name = 'key'
                if flag in v:
                    name = 'value'
                if name:
                    pos.append({
                        'pos': name,
                        'key': k,
                        'detail': token
                    })
            if flag in token['text']:
                pos.append({
                    'pos': 'text',
                    'detail': token
                })
        if flag in tokens[-1].get('comment', ''):
            pos.append({
                'pos': 'comment',
                'value': tokens[-1].get('comment', '')
            })
    return pos
