// Controlled async tests of the shipped UI script, not browser acceptance.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

const html = await readFile(
  new URL("../src/paramguard/static/assisted.html", import.meta.url),
  "utf8",
);
const script = html.match(
  /<script nonce="__PG_NONCE__">([\s\S]*?)<\/script>/,
)[1];
class Element {
  constructor() {
    this.value = "";
    this.hidden = false;
    this.disabled = false;
    this.children = [];
    this.options = [];
    this.handlers = {};
    this.classList = { add() {}, remove() {} };
  }
  append(...children) {
    this.children.push(...children);
  }
  replaceChildren(...children) {
    this.children = children;
    this.options = children.filter((c) => c.option);
  }
  add(option) {
    this.options.push(option);
  }
  addEventListener(event, fn) {
    this.handlers[event] = fn;
  }
  setAttribute() {}
  remove() {}
  showModal() {
    this.open = true;
  }
  close() {
    this.open = false;
  }
  click() {
    this.clicked = true;
  }
  get dataset() {
    return (this._data ??= Object.create(null));
  }
}
const response = (body) => ({ ok: true, status: 200, json: async () => body });
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => (resolve = r));
  return { promise, resolve };
};
const tick = () => new Promise((resolve) => setImmediate(resolve));
const A = "a".repeat(32),
  B = "b".repeat(32);
function state(id) {
  return {
    job_id: id,
    label: "SYNTHETIC " + id[0],
    state: "READY",
    revision: 8,
    manifest_hash: id.repeat(2),
    total: 1,
    reviewed: 0,
    counts: {
      SAME: 1,
      DIFFERENT: 0,
      NOT_LOCATED: 0,
      MULTIPLE_CANDIDATES: 0,
      UNCERTAIN: 0,
    },
    pages: [],
    items: [
      { ordinal: 0, key: "P1", label: "P1", status: "SAME", human: null },
    ],
    filtered_total: 1,
    can_finish: false,
  };
}
function item(id) {
  return {
    job: id,
    ordinal: 0,
    key: "P1",
    label: "P1",
    state: "READY",
    status: "SAME",
    human: null,
    reason: "",
    revision: 8,
    manifest_hash: id.repeat(2),
    machine: { left: [], right: [], left_selected: null, right_selected: null },
  };
}
function setup(fetcher) {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  get("filter").value = "all";
  const document = {
    getElementById: get,
    createElement: () => new Element(),
    createTextNode: (text) => ({ textContent: text }),
    querySelectorAll: () => [],
    addEventListener() {},
    body: new Element(),
    activeElement: null,
  };
  const context = vm.createContext({
    document,
    location: { hash: "" },
    crypto: webcrypto,
    console,
    URLSearchParams,
    TextDecoder,
    Blob,
    URL,
    clearTimeout,
    setTimeout,
    Option: function (text, value) {
      const e = new Element();
      e.option = true;
      e.textContent = text;
      e.value = value;
      return e;
    },
    FileReader: class {
      readAsDataURL() {
        this.result = "data:image/png;base64,c3ludGhldGlj";
        queueMicrotask(() => this.onload());
      }
    },
    fetch: async (path, options) =>
      path === "/api/jobs" && !options?.method
        ? response({ jobs: [] })
        : fetcher(path, options),
  });
  vm.runInContext(script, context, { timeout: 2000 });
  return {
    context,
    get,
    document,
    run: (code) => vm.runInContext(code, context, { timeout: 2000 }),
  };
}

// Old task detail cannot be submitted under a new task's correct CAS binding.
{
  const pending = deferred(),
    posts = [];
  const ui = setup(async (path, options) => {
    if (options?.method) {
      posts.push({ path, body: JSON.parse(options.body) });
      return response({ revision: 9, manifest_hash: B.repeat(2) });
    }
    if (path.includes("/items/")) return pending.promise;
    return response(state(B));
  });
  await tick();
  ui.run(
    `job=${JSON.stringify(state(A))};detail=${JSON.stringify(item(A))};selected=0;`,
  );
  const loading = ui.run(`loadJob('${B}')`);
  await tick();
  assert.equal(ui.run("detail"), null);
  await ui.run("record('DIFFERENT')");
  assert.equal(posts.length, 0);
  pending.resolve(response(item(B)));
  await loading;
  await ui.run(
    "mutate('review',{ordinal:0,verdict:'UNABLE',reason:'synthetic'})",
  );
  assert.equal(posts.length, 1);
  assert.equal(posts[0].path, `/api/jobs/${B}/review`);
  assert.equal(posts[0].body.manifest_hash, B.repeat(2));
}
// A late old request must not pull the user out of a fresh new-task form.
{
  const pending = deferred();
  const ui = setup(() => pending.promise);
  await tick();
  const loading = ui.run(`loadJob('${A}')`);
  ui.run("resetSetup()");
  pending.resolve(response(state(A)));
  await loading;
  assert.equal(ui.run("job"), null);
  assert.equal(ui.get("setup").hidden, false);
}
// Replacement file selections are rejected while the accepted queue uploads.
{
  const pending = deferred(),
    uploaded = [];
  const draft = { ...state(A), state: "DRAFT", pages: [] };
  const ui = setup(async (path, options) => {
    if (options?.method) {
      uploaded.push(JSON.parse(options.body).name);
      return pending.promise;
    }
    return response(draft);
  });
  await tick();
  ui.run(
    `job=${JSON.stringify(draft)};files.left=[{name:'old.png',size:10}];setBusy(true);`,
  );
  const uploading = ui.run("uploadFiles()");
  await tick();
  ui.run("selectFiles('left',[{name:'new-never-uploaded.png',size:10}])");
  assert.equal(ui.run("files.left[0].name"), "old.png");
  assert.equal(ui.get("left-files").disabled, true);
  pending.resolve(response({ revision: 9, manifest_hash: A.repeat(2) }));
  await uploading;
  assert.deepEqual(uploaded, ["old.png"]);
  assert.equal(ui.run("files.left.length"), 0);
}
// The newest item response wins, even when an older request returns last.
{
  const zero = deferred(),
    one = deferred();
  const ui = setup((path) =>
    path.endsWith("/0") ? zero.promise : one.promise,
  );
  await tick();
  ui.run(`job=${JSON.stringify(state(A))};`);
  const old = ui.run("selectItem(0)"),
    recent = ui.run("selectItem(1)");
  one.resolve(response({ ...item(A), ordinal: 1, key: "P2" }));
  await recent;
  zero.resolve(response(item(A)));
  await old;
  assert.equal(ui.run("detail.key"), "P2");
}
// Busy cleanup must preserve real pagination and completion boundaries.
{
  const ui = setup(() => response({}));
  await tick();
  ui.run(`job=${JSON.stringify(state(A))};setBusy(false);`);
  assert.equal(ui.get("previous-page").disabled, true);
  assert.equal(ui.get("next-page").disabled, true);
  assert.equal(ui.get("finish").disabled, true);
}
// A draft's frozen target picker becomes usable again on a new task.
{
  const ui = setup(() => response({ ...state(A), state: "DRAFT" }));
  await tick();
  await ui.run(`loadJob('${A}')`);
  assert.equal(ui.get("target-file").disabled, true);
  ui.run("resetSetup()");
  assert.equal(ui.get("target-file").disabled, false);
}
// Old original-image buttons are harmless while their detail is replaced.
{
  const ui = setup(() => response({}));
  await tick();
  ui.run(`job=${JSON.stringify(state(A))};detail=null;loadingView=true;`);
  ui.run("openImage('left',false)");
  assert.equal(ui.get("image-dialog").open, undefined);
}
// Non-item operations are also blocked while a new task is loading.
{
  const pending = deferred(),
    calls = [];
  const ui = setup((path, options) => {
    calls.push(path);
    return path.includes("/items/") ? response(item(B)) : pending.promise;
  });
  await tick();
  ui.run(`job=${JSON.stringify(state(A))};`);
  const loading = ui.run(`loadJob('${B}')`);
  await tick();
  for (const id of ["export", "start-draft", "upload-more", "create-job"])
    assert.equal(ui.get(id).disabled, true);
  await ui.get("export").handlers.click();
  await ui.get("start-draft").handlers.click();
  await assert.rejects(ui.run("mutate('start')"), /正在切换任务/);
  assert.equal(calls.length, 1);
  pending.resolve(response(state(B)));
  await loading;
}
// A report is always named for the requested task, never a later global task.
{
  const pending = deferred();
  const ui = setup(() => pending.promise);
  await tick();
  ui.run(`job=${JSON.stringify(state(A))};`);
  const exporting = ui.get("export").handlers.click();
  await tick();
  ui.run(`job=${JSON.stringify(state(B))};`);
  pending.resolve(response({ job_id: A }));
  await exporting;
  assert.equal(
    ui.document.body.children.at(-1).download,
    "ParamGuard-aaaaaaaa.json",
  );
}
// A saved region followed by a failed refresh must show a visible truthful error.
{
  const ui = setup((path, options) =>
    options?.method
      ? response({ revision: 9, manifest_hash: A.repeat(2) })
      : {
          ok: false,
          json: async () => ({
            error: "UNAVAILABLE",
            message: "Synthetic refresh failure",
          }),
        },
  );
  await tick();
  ui.run(
    `job=${JSON.stringify(state(A))};detail=${JSON.stringify(item(A))};selected=0;modal={ordinal:0,side:'left',page:{page_id:'page'}};`,
  );
  ui.get("image-dialog").showModal();
  ui.get("message").textContent = "OLD saved human record";
  await ui.get("save-region").handlers.click();
  assert.equal(ui.get("image-dialog").open, false);
  assert.equal(ui.get("message").hidden, false);
  assert.match(ui.get("message").textContent, /区域已保存，旧人工结论已失效/);
  assert.equal(ui.run("loadingView"), false);
  assert.equal(ui.run("busy"), false);
}
// A failed item read keeps old detail unusable and leaves refresh available.
{
  const ui = setup(() => ({
    ok: false,
    json: async () => ({ message: "Synthetic item failure" }),
  }));
  await tick();
  ui.run(`job=${JSON.stringify(state(A))};`);
  await assert.rejects(ui.run("selectItem(0)"), /Synthetic item failure/);
  assert.equal(ui.run("detail"), null);
  assert.equal(ui.run("loadingView"), false);
  assert.equal(ui.get("refresh").disabled, false);
}
console.log("11 assisted UI async regression checks passed");
