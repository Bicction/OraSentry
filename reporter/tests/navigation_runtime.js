// Execute the real template script with a small deterministic geometry/event model.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync(process.argv[2], 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];

function world({hash = '', observer = true} = {}) {
    const events = {document: {}, window: {}};
    const frames = [];
    const ids = ['overview', 'section-db', 'check-db-表空间使用概览', 'check-db-采集完整性', 'report-summary'];
    const tops = [0, 400, 600, 1000, 1800];
    const win = {innerHeight: 800, scrollY: 0, location: {hash}, requestAnimationFrame: f => frames.push(f),
        addEventListener: (name, fn) => { events.window[name] = fn; }};
    const targets = ids.map((id, index) => ({id, top: tops[index], index,
        getBoundingClientRect() { return {top: this.top - win.scrollY, bottom: this.top + 180 - win.scrollY}; },
        compareDocumentPosition(other) { return this.index < other.index ? 4 : 2; }}));
    const sidebar = {scrollTop: 0, clientHeight: 150, getBoundingClientRect: () => ({top: 0, bottom: 150})};
    // Deliberately shuffle nav links: scroll tracking must still follow body positions.
    const links = [targets[0], targets[1], targets[3], targets[2], targets[4]].map((target, i) => {
        const attrs = {href: '#' + target.id};
        const classes = new Set();
        return {attrs, classes, classList: {toggle: (c, on) => on ? classes.add(c) : classes.delete(c)},
            getAttribute: n => attrs[n], setAttribute: (n, v) => attrs[n] = v,
            removeAttribute: n => delete attrs[n],
            getBoundingClientRect: () => ({top: i * 40 - sidebar.scrollTop, bottom: i * 40 + 30 - sidebar.scrollTop})};
    });
    const doc = {documentElement: {scrollHeight: 2200},
        querySelector: () => sidebar,
        querySelectorAll: selector => selector === '.extra-toggle' ? [] : links,
        getElementById: id => targets.find(t => t.id === id) || null,
        addEventListener: (name, fn) => { events.document[name] = fn; }};
    let observerCallback;
    function Observer(fn) { observerCallback = fn; this.observe = () => {}; }
    if (observer) { win.IntersectionObserver = Observer; }
    vm.runInNewContext(script, {window: win, document: doc, Node: {DOCUMENT_POSITION_FOLLOWING: 4}, IntersectionObserver: Observer});
    const flush = () => { while (frames.length) { frames.shift()(); } };
    events.document.DOMContentLoaded();
    return {win, targets, links, sidebar, flush,
        fire: (surface, name, event = {}) => { if (events[surface][name]) { events[surface][name](event); } },
        observe: entries => { observerCallback(entries); },
        active: () => links.filter(l => l.classes.has('active')).map(l => l.attrs.href.slice(1))};
}

let w = world(); w.flush();
assert.deepEqual(w.active(), ['overview']);
w.win.scrollY = 950; w.fire('window', 'scroll'); w.flush();
assert.deepEqual(w.active(), ['check-db-采集完整性']);
w.observe([{isIntersecting: true, target: w.targets[1]}]); w.flush();
assert.deepEqual(w.active(), ['check-db-采集完整性'], 'observer batches must not select a containing section');

const first = 'check-db-表空间使用概览';
w = world({hash: '#' + encodeURIComponent(first)});
w.win.scrollY = 588; w.flush();
assert.deepEqual(w.active(), [first], 'encoded Chinese deep link');
assert.equal(w.links.find(l => l.attrs.href === '#' + first).attrs['aria-current'], 'location');

// A short following row must not steal the clicked item highlight.
w.targets[3].top = 650;
w.fire('document', 'click', {target: {closest: () => ({getAttribute: () => '#' + first})}});
w.fire('window', 'scroll'); w.flush();
assert.deepEqual(w.active(), [first], 'contents/action clicks pin the exact target');
assert.equal(w.win.scrollY, 588, 'menu following must not scroll the page');
w.fire('document', 'wheel'); w.win.scrollY = 660; w.fire('window', 'scroll'); w.flush();
assert.deepEqual(w.active(), ['check-db-采集完整性'], 'manual scrolling releases clicked target');

w.win.scrollY = 588; w.win.location.hash = '#' + encodeURIComponent(first);
w.fire('window', 'hashchange'); w.flush();
assert.deepEqual(w.active(), [first], 'history navigation');
w.win.scrollY = 1400; w.fire('document', 'keydown', {key: 'End'}); w.fire('window', 'scroll'); w.flush();
assert.deepEqual(w.active(), ['report-summary'], 'bottom of report selects last section');
assert.ok(w.sidebar.scrollTop > 0);
assert.equal(w.win.scrollY, 1400);

w = world({observer: false, hash: '#%E0%A4%A'}); w.flush();
assert.deepEqual(w.active(), ['overview'], 'invalid fragments are harmless');
w.win.scrollY = 950; w.fire('window', 'scroll'); w.flush();
assert.deepEqual(w.active(), ['check-db-采集完整性'], 'scroll tracking works without IntersectionObserver');
console.log('Navigation behavior: Chinese links, clicks, scroll, observer batches, history, bottom and sidebar scrolling passed.');

w = world();
w.targets[3].top = w.targets[2].top;
w.win.scrollY = 600; w.fire('window', 'scroll'); w.flush();
assert.deepEqual(w.active(), [first], 'same-row host cards select the first entry');
