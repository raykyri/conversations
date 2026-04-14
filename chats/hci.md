~ What are some novel HCI interfaces that I could implement inside a text editor?
⏺ - Semantic zoom for code: pinch/keys to smoothly move between tokens, lines, blocks, functions, and architecture views.
  - Intent lens: hold a modifier to reveal why code exists, likely next edits, and affected symbols inline.
  - Temporal scrubbing: drag through file history as if it were a timeline, with edits animating in place.
  - Conversational regions: attach a mini dialogue thread to any selection, so reasoning lives beside code instead of in comments.
  - Gesture macros: draw simple shapes or strokes over text to refactor, extract, duplicate, wrap, or reorder.
  - Attention heatmap: visualize what you edited recently, what breaks often, and what collaborators touch most.
  - Constraint editing: describe an invariant like “keep behavior, reduce allocations,” then make edits under that live constraint.
  - Multi-cursor by meaning: select “all error paths,” “all API boundaries,” or “all state mutations,” not just text matches.
  - Spatial memory mode: persistent 2D layout where files, symbols, and notes stay arranged like a desk rather than tabs.
  - Runtime overlay: values, logs, traces, and performance data appear directly on the code they came from.
  - Reading modes for intent: switch between implementation view, dataflow view, dependency view, and user-impact view.
  - Proximity collaboration: nearby collaborators’ cursors become soft presence indicators with lightweight handoff gestures.
  - Voice-to-structure editing: speak commands like “extract this into a pure helper and move tests with it.”
  - Speculative editing: branch a local “what if” version inline, compare outcomes side by side, then merge selectively.
  - Cognitive bookmarks: save not just a location, but a task state like “confusing,” “needs proof,” or “resume here.”
~ What about ones that make use of recent AI capabilities? Or assuming I have an editor environment with deep AI integration (full control of CodeMirror, inline triggers for different models, etc.)
⏺ Here are some ideas that lean heavily on AI integration:

  **Inline intent negotiation.** You type a rough sketch or pseudocode and the editor enters a negotiation mode where it proposes a completion, you tweak part of it, and it re-proposes around your tweaks. Not a single accept/reject cycle but a back-and-forth convergence where your edits are treated as constraints on the next suggestion.

  **Ambient type and contract inference.** The editor continuously infers likely types, preconditions, postconditions, and invariants from your untyped code and displays them as faint annotations. You promote any annotation to real code with a keystroke. Disagreements between your code and the inferred contracts get highlighted like lint errors.

  **Explanation depth slider.** Select any region and get an explanation. A slider controls depth: at one end you get a one-sentence summary, at the other end you get a line-by-line walkthrough with context about why each decision was likely made. The explanation updates continuously as you drag.

  **Semantic diff and merge.** Instead of line-based diffs, the AI produces a structured description of what changed in meaning. Merge conflicts are presented as competing intentions rather than competing text, and you resolve them by choosing behaviors.

  **Ghost collaborator.** An AI agent that watches your editing patterns and silently prepares likely next files to open, likely next functions to change, likely test updates, and likely documentation patches. These appear as a faint "ghost" tab or sidebar you can pull from when ready.

  **Edit-by-example.** Make one edit manually. The editor generalizes your intent and highlights all other locations where a similar transformation could apply, ranked by confidence. You approve, skip, or correct each one, and corrections refine the pattern.

  **Live invariant testing.** As you type, the editor generates and runs micro-tests in the background against what it believes the code should do. If your edit breaks an inferred invariant, you get an inline warning before you even save, even if no formal tests exist.

  **Context-aware hole filling.** Leave explicit holes like `???` or `TODO` and the editor fills them not just from local context but from your recent conversation threads, open browser tabs (if permitted), git history, and related files. Each fill comes with a provenance tooltip showing what context drove it.

  **Natural language breakpoints.** Instead of setting a breakpoint on a line, you describe a condition in English like "when the user object has no email but the request expects one" and the AI translates it to a conditional breakpoint or logpoint in the right location.

  **Refactor by describing the goal.** Instead of choosing a named refactoring, you describe what you want the code to feel like afterward: "this module should have no side effects" or "callers shouldn't need to know about the cache." The editor proposes a sequence of concrete refactoring steps to get there.

  **Reading mode synthesis.** Ask the editor to generate a "tour" of an unfamiliar codebase. It produces a guided, ordered reading list of files and regions with inline narrative annotations, like a textbook chapter written on top of real code.

  **Inline model switching by task.** Different selections or regions automatically route to different models based on what you're doing. A fast small model handles autocomplete, a reasoning model handles refactoring suggestions, a code-specific model handles test generation, and you can override per region.

  **Predictive conflict detection.** As you edit, the AI checks your changes against recent commits by collaborators that haven't been merged yet and warns you early that you're likely heading toward a merge conflict, with suggestions for how to structure your changes to avoid it.

  **Commit narration.** When you're ready to commit, the editor doesn't just summarize the diff. It generates a narrative of your session: what you explored, what you tried and reverted, what you settled on and why, producing a commit message that captures intent rather than just outcome.
~ What are cognitive bookmarks? Have those been implemented before, in either research papers, lab prototypes, demos, or production environments?
⏺ Cognitive bookmarks are the idea of saving not just a location in code but the mental state or task context around that location. A regular bookmark says "line 47 of foo.js." A cognitive bookmark says "line 47 of foo.js — I was confused about why this mutex is needed, I think it relates to the race condition in the handler, and I need to come back after reading the logging module."

  The core insight is that when you leave a piece of code and return later, the expensive part isn't finding the line again — it's reconstructing why you were there, what you were thinking, and what you planned to do next. A cognitive bookmark tries to capture and restore that context.

  The concept draws from a few threads:

  **Research lineage.** The idea connects to work on task-aware development environments. Gail Murphy and Mik Kersten's Mylyn project (originally Mylar, around 2005-2006 at UBC) tracked "task contexts" in Eclipse — the set of files and elements you interacted with during a task. When you switched tasks, it could restore the relevant working set. This is probably the closest production-grade ancestor. It shipped as a real Eclipse plugin and was widely used.

  There's also the broader HCI research on "knowledge management in software development" and "programmer interrupted" studies (Chris Parnin's work around 2010-2013 is notable here), which documented how costly context switches are and explored what artifacts could help programmers resume interrupted tasks.

  **Related concepts.** Literate programming (Knuth) captures reasoning alongside code but at authoring time, not as a transient navigation aid. Code annotations and TODO systems are a very crude version. Visual Studio's "task list" and JetBrains' scratch files and notes are lightweight steps in this direction.

  **What hasn't really been built.** The specific framing of bookmarks that carry structured cognitive metadata — your current hypothesis, your confusion, your planned next step, related open questions — as a first-class editor primitive with AI assistance to help capture and restore that state, that hasn't been built as a polished system as far as I'm aware. Pieces exist: Mylyn did task context, various tools do annotations, but the synthesis of bookmark + mental state + AI-assisted context reconstruction is still mostly an open design space.

  I should caveat that my knowledge has a cutoff and I may be missing recent prototypes or indie tools. But the term "cognitive bookmarks" as I used it was more of a design concept than a reference to a specific existing system.