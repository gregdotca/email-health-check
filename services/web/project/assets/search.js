// The documentation's search box: results as you type, searched here in the browser from /docs/search.json
// (fetched the first time the box is used), so nothing typed leaves the page until Enter opens the results page.
// Without this script the box is a plain form for /docs/search/, which docs.py answers with the same search:
// keep searchTerms(), search(), snippet() and highlight() in step with docs.py (tests/test_docs.py runs both).
"use strict";

const MAX_QUERY = 100, MAX_TERMS = 8, MAX_SHOWN = 8;
const EDGE_PUNCTUATION = "\"'“”‘’,;:!?()[]";
const SNIPPET_BEFORE = 60, SNIPPET_LENGTH = 180;
// What separates words in a query: Python's whitespace and JavaScript's, spelled out so both split the same
const SPACE = /[\t\n\v\f\r \x1c-\x1f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/;

function strip(term) {
    let a = 0, b = term.length;
    while (a < b && EDGE_PUNCTUATION.includes(term[a])) a++;
    while (b > a && EDGE_PUNCTUATION.includes(term[b - 1])) b--;
    return term.slice(a, b);
}

// Text as a list of characters, counted as Python counts them (an emoji is one, not two)
function chars(text) {
    return Array.from(text);
}

// Lower case, one character for one, so positions found in it are positions in the text (a character whose
// lower case is longer, like İ, stays as it is): as docs.fold
function fold(text) {
    return chars(text).map(c => { const low = c.toLowerCase(); return chars(low).length === 1 ? low : c; }).join("");
}

// Where a list of characters holds another, from a position on (-1 if it doesn't)
function find(hay, term, from = 0) {
    for (let i = from; i + term.length <= hay.length; i++) if (startsAt(hay, term, i)) return i;
    return -1;
}

function startsAt(hay, term, i) {
    for (let j = 0; j < term.length; j++) if (hay[i + j] !== term[j]) return false;
    return true;
}

// The query's words, one space apart, cut to MAX_QUERY characters
function squash(query) {
    return chars(query.split(SPACE).join(" ").replace(/^ +| +$/g, "")).slice(0, MAX_QUERY).join("");
}

// The lower-case words of a query (at most MAX_TERMS, each once), or null for one that holds an address
// (anywhere in it, even past MAX_QUERY)
function searchTerms(query) {
    if (query.includes("@")) return null;
    const terms = [];
    for (const word of fold(squash(query)).split(" ")) {
        const term = strip(word);
        if (term && !terms.includes(term)) terms.push(term);
    }
    return terms.slice(0, MAX_TERMS);
}

function count(text, term) {
    return text.split(term).length - 1;
}

// Each entry's heading, page title and text, folded once
const FOLDED = new WeakMap();

function folded(entry) {
    if (!FOLDED.has(entry)) FOLDED.set(entry, [fold(entry.heading), fold(entry.page), fold(entry.text)]);
    return FOLDED.get(entry);
}

// The entries holding every term, best first (the same scores as docs.search)
function search(terms, index) {
    const phrase = terms.join(" "), found = [];
    index.forEach((entry, i) => {
        const [heading, page, text] = folded(entry);
        if (!terms.length || terms.some(t => !heading.includes(t) && !page.includes(t) && !text.includes(t))) return;
        let score = 0;
        for (const t of terms) score += 8 * heading.includes(t) + 2 * page.includes(t) + Math.min(count(text, t), 3);
        if (terms.length > 1) score += 10 * heading.includes(phrase) + 4 * text.includes(phrase);
        found.push([-score, i, entry]);
    });
    found.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    return found.map(f => f[2]);
}

// About SNIPPET_LENGTH characters of text around the first term found in it, cut at spaces
function snippet(text, terms) {
    const all = chars(text), low = chars(fold(text));
    const positions = terms.map(t => find(low, chars(t))).filter(p => p >= 0);
    const first = positions.length ? Math.min(...positions) : 0;
    let start = Math.max(0, first - SNIPPET_BEFORE);
    if (start) {
        const space = all.indexOf(" ", start);
        if (space >= 0 && space < first) start = space + 1;
    }
    let end = start + SNIPPET_LENGTH;
    if (end < all.length) {
        const space = all.lastIndexOf(" ", end - 1);
        if (space > first) end = space;
    }
    return (start ? "… " : "") + all.slice(start, end).join("").trim() + (end < all.length ? " …" : "");
}

// [[part, matched]] with every term marked, longer terms first where they overlap
function highlight(text, terms) {
    const all = chars(text), low = chars(fold(text)), parts = [];
    const ordered = terms.map(chars).sort((a, b) => b.length - a.length);
    let i = 0;
    while (i < all.length) {
        const term = ordered.find(t => startsAt(low, t, i));
        if (term) {
            parts.push([all.slice(i, i + term.length).join(""), true]);
            i += term.length;
        } else {
            if (parts.length && !parts[parts.length - 1][1]) parts[parts.length - 1][0] += all[i];
            else parts.push([all[i], false]);
            i++;
        }
    }
    return parts;
}

function marked(parts) {
    const span = document.createElement("span");
    for (const [part, matched] of parts) {
        if (matched) span.appendChild(document.createElement("mark")).textContent = part;
        else span.appendChild(document.createTextNode(part));
    }
    return span;
}

function start(form) {
    const input = form.querySelector("input[name=q]"), panel = form.querySelector(".docs-search-panel");
    const list = form.querySelector(".docs-search-list"), message = form.querySelector(".docs-search-message");
    const all = form.querySelector(".docs-search-all"), status = form.querySelector("[role=status]");
    let index = null, loading = null, active = -1, shown = [], generation = 0;

    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-controls", list.id);
    input.setAttribute("aria-expanded", "false");
    form.classList.add("ready");

    function load() {
        loading = loading || fetch(form.dataset.index, {credentials: "same-origin"})
            .then(r => r.ok ? r.json() : Promise.reject(r.status))
            .then(data => { index = data; })
            .catch(() => { loading = null; throw new Error("no index"); });
        return loading;
    }

    function open(isOpen) {
        if (!isOpen) generation++;  // a search still waiting for the index mustn't open the list again
        panel.hidden = !isOpen;
        input.setAttribute("aria-expanded", String(isOpen));
        if (!isOpen) select(-1);
    }

    function say(text, link) {
        message.replaceChildren(text);
        if (link) {
            const a = message.appendChild(document.createElement("a"));
            a.href = link.href;
            a.textContent = link.text;
            message.append(".");
        }
        message.hidden = false;
    }

    function select(i) {
        const options = list.children;
        if (active >= 0 && options[active]) options[active].setAttribute("aria-selected", "false");
        active = i;
        if (i >= 0 && options[i]) {
            options[i].setAttribute("aria-selected", "true");
            input.setAttribute("aria-activedescendant", options[i].id);
            options[i].scrollIntoView({block: "nearest"});
        } else {
            input.removeAttribute("aria-activedescendant");
        }
    }

    function update() {
        const query = squash(input.value), terms = searchTerms(input.value), wanted = ++generation;
        select(-1);
        list.replaceChildren();
        message.hidden = true;
        all.hidden = true;
        shown = [];
        if (terms === null) {
            say("The search doesn't take email addresses. To find a report, ", {href: "/", text: "look it up on the homepage"});
            status.textContent = "The search doesn't take email addresses.";
            return open(true);
        }
        if (!terms.length) {
            status.textContent = "";
            return open(false);
        }
        if (!index) {
            say("Searching…");
            status.textContent = "Searching…";
            open(true);
            load().then(() => {
                if (wanted === generation) update();
            }, () => {
                if (wanted !== generation) return;
                say("The search isn't available right now. Press Enter to search.");
                status.textContent = "The search isn't available right now. Press Enter to search.";
            });
            return;
        }
        const found = search(terms, index);
        shown = found.slice(0, MAX_SHOWN);
        shown.forEach((entry, i) => {
            const li = list.appendChild(document.createElement("li"));
            li.id = `docs-search-option-${i}`;
            li.setAttribute("role", "option");
            li.setAttribute("aria-selected", "false");
            const a = li.appendChild(document.createElement("a"));
            a.href = entry.url;
            a.tabIndex = -1;
            a.appendChild(marked(highlight(entry.heading, terms))).className = "docs-search-title";
            a.appendChild(document.createElement("span")).className = "docs-search-where";
            a.lastChild.textContent = entry.where;
            a.appendChild(marked(highlight(snippet(entry.text, terms), terms))).className = "docs-search-snippet";
        });
        if (!found.length) say("Nothing found. Try fewer or shorter words.");
        if (found.length > MAX_SHOWN) {
            all.href = `${form.action}?q=${encodeURIComponent(query)}`;
            all.textContent = `See all ${found.length} results`;
            all.hidden = false;
        }
        status.textContent = found.length ? `${found.length} result${found.length === 1 ? "" : "s"}` : "Nothing found";
        open(true);
    }

    input.addEventListener("input", update);
    let returning = false;  // the focus coming back to the box after Escape: leave the list closed
    input.addEventListener("focus", () => {
        load().catch(() => {});
        if (input.value.trim() && !returning) update();
        returning = false;
    });
    input.addEventListener("keydown", e => {
        if (e.isComposing || e.keyCode === 229) return;  // keys that pick or confirm an input method's text
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            if (panel.hidden) update();
            const options = list.children.length;
            if (!options) return;
            e.preventDefault();
            const step = e.key === "ArrowDown" ? 1 : -1;
            select(active < 0 ? (step > 0 ? 0 : options - 1) : (active + step + options) % options);
        } else if (e.key === "Enter") {
            if (active >= 0 && shown[active]) {
                const url = shown[active].url;
                e.preventDefault();
                open(false);
                window.location.href = url;
            } else if (searchTerms(input.value) === null) {
                e.preventDefault();  // never put an address in the results page's URL
            }
        }
    });
    // Escape closes the list (from the box or from "See all results"), then a second one empties the box
    form.addEventListener("keydown", e => {
        if (e.key !== "Escape" || e.isComposing) return;
        if (!panel.hidden) {
            open(false);
            if (e.target !== input) {
                returning = true;
                input.focus();
            }
        } else if (e.target === input && input.value) {
            input.value = "";
            update();
        } else {
            return;
        }
        e.preventDefault();
    });
    form.addEventListener("submit", e => {
        if (searchTerms(input.value) === null) e.preventDefault();
    });
    // Keep the focus in the box while a result is clicked (some browsers don't focus links on click)
    panel.addEventListener("mousedown", e => e.preventDefault());
    list.addEventListener("click", () => open(false));
    form.addEventListener("focusout", e => {
        if (!form.contains(e.relatedTarget)) open(false);
    });
    // "/" anywhere on the page jumps to the box, as on many documentation sites
    document.addEventListener("keydown", e => {
        const target = e.target;
        if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
        if (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return;
        e.preventDefault();
        input.focus();
        input.select();
    });
}

if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
        const form = document.querySelector(".docs-search");
        if (form && window.fetch) start(form);
    });
} else if (typeof module !== "undefined") {
    module.exports = {searchTerms, search, snippet, highlight, squash, start};  // for tests/test_docs.py
}
