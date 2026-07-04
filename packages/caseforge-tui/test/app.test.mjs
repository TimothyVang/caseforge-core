import { test } from "node:test"
import assert from "node:assert/strict"
import { keyOf, reduce, initialState } from "../dist/src/app.js"

test("keyOf maps arrows, vim keys, enter, back, quit", () => {
  assert.equal(keyOf("\x1b[A"), "up")
  assert.equal(keyOf("k"), "up")
  assert.equal(keyOf("\x1b[B"), "down")
  assert.equal(keyOf("j"), "down")
  assert.equal(keyOf("\r"), "enter")
  assert.equal(keyOf("q"), "back")
  assert.equal(keyOf("\x03"), "quit")
  assert.equal(keyOf("z"), "other")
})
test("picker cursor moves within bounds", () => {
  let s = initialState
  assert.equal(s.cursor, 0)
  s = reduce(s, "up", 3) // clamp at 0
  assert.equal(s.cursor, 0)
  s = reduce(s, "down", 3)
  assert.equal(s.cursor, 1)
  s = reduce(s, "down", 3)
  s = reduce(s, "down", 3) // clamp at last
  assert.equal(s.cursor, 2)
})
test("enter opens the case; back returns to picker", () => {
  let s = reduce(initialState, "enter", 3)
  assert.equal(s.view, "case")
  s = reduce(s, "back", 3)
  assert.equal(s.view, "picker")
})
test("enter with no runs is a no-op; q on picker quits", () => {
  assert.equal(reduce(initialState, "enter", 0).view, "picker")
  assert.equal(reduce(initialState, "back", 3).quit, true)
})
test("reduce is immutable (returns a new object)", () => {
  const s = initialState
  const s2 = reduce(s, "down", 3)
  assert.notEqual(s, s2)
  assert.equal(s.cursor, 0) // original unchanged
})
