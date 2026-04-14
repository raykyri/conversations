

~ It seems like AI is affecting people I know in technical domains a lot more than it's affecting people outside. Roughly, in order, programmers > analysts > actuaries > lawyers > doctors > people in the trades and manual labor. I'm sure people have made observations about this, but is there anyone who has tried to extrapolate this to how a software singularity would go?
⏺ You're touching on something that a number of thinkers have discussed, though the framing varies.

  The basic observation — that AI impacts cognitive-symbolic work before physical work — is well established. Economists like Erik Brynjolfsson and Daron Acemoglu have written extensively about how automation tends to hit "routine cognitive" tasks first. What's somewhat surprising in the current wave is that it's hitting *non-routine* cognitive work too, which wasn't what older models predicted. The ordering you describe roughly tracks with how formalized and digitized a domain's inputs and outputs are.

  On the singularity extrapolation specifically, a few threads worth knowing about:

  **Moravec's Paradox** is the classic framing — reasoning is cheap, sensorimotor skills are hard. Hans Moravec pointed this out in the 1980s. Your ordering is basically Moravec's paradox playing out in the labor market in real time.

  **Robin Hanson** has probably thought most carefully about the economic dynamics of a software-centric intelligence explosion. His work on "the em economy" and his broader writing on AI foom scenarios engages with the question of what happens when AI recursively improves the domain it's best at (software) before anything else. The implication is that a singularity could be very "lumpy" — massively transforming some sectors while others lag for a long time because the physical world is a bottleneck.

  **Leopold Aschenbrenner's "Situational Awareness"** memo explicitly argues that AI will first automate AI research itself, creating a recursive loop in the software domain specifically, well before it conquers physical tasks. This is essentially your gradient taken to its logical extreme.

  **Eliezer Yudkowsky** has pushed back on the idea that the gradient you observe would persist — his argument is that a sufficiently intelligent system would find creative ways around physical bottlenecks (e.g., by designing better robots, or by finding purely informational leverage points that have outsized physical-world effects). So the ordering might hold for narrow AI but collapse suddenly with AGI.

  The interesting tension is between people who think the gradient you're seeing is a durable feature of how a singularity would unfold (Hanson-style: slow, uneven, bottlenecked by atoms) versus those who think it's a temporary artifact that would be quickly overcome once AI crosses a general capability threshold (Yudkowsky-style: fast, convergent, the software domain is just the entry point).

  Your lived observation is genuinely useful data for thinking about which of these pictures is more right, at least in the near term.

  {>> lol <<}

  {>> could probably build a better set of references here too, this is pretty surface level <<}
~ How recent is Acemoglu's work? Has he spoken or written on this since around 2023?
⏺ Yes, Acemoglu has been quite active on this topic recently. He published a notable paper in 2024 — "The Simple Macroeconomics of AI" — where he argued that AI's economic impact would be more modest than the hype suggests, partly because it would affect a limited subset of tasks and partly because of the kinds of bottlenecks you're observing (physical world, human judgment, etc.). He estimated something like a 0.5% GDP gain over a decade, which was seen as a splash of cold water relative to the more breathless predictions.

  He's also been vocal in public commentary around 2023-2024, pushing back on Goldman Sachs and McKinsey-style projections that assume AI will smoothly transform most of the economy. His core argument is that the tasks AI can actually do well are a narrower slice than people assume, and that even within cognitive work there are complements and bottlenecks that slow adoption.

  That said, I want to flag some uncertainty here — I'm confident about the broad strokes of his recent position and the existence of that 2024 paper, but I could be slightly off on specific details like the exact GDP figure. His recent stance is genuinely more conservative than most economists working on AI, which is notable given that he's one of the most prominent economists alive (Nobel Prize 2024, in fact, shared with Simon Johnson and James Robinson, though that was for institutional economics rather than AI work).

  So yes, he's very much a live voice in this conversation and his recent work directly engages with the pattern you're describing.
~ Okay. I'm interested in this difference between routine and non-routine cognitive work. It seems like some domains like analyst and actuarial work are relatively routine. Low-level software engineering is routine, while high-level software work is less routine. There are also some other factors at play around trust, liability, and the importance of a human interface.
⏺ Right, and I think you're identifying something that the clean "routine vs non-routine" taxonomy actually struggles with. The original framework comes from Autor, Levy, and Murnane (around 2003), and it was built to explain the hollowing out of middle-skill jobs by earlier waves of computerization. It worked well for that era — data entry, bookkeeping, assembly line work got automated, while both janitors and CEOs were safe.

  But the current wave is messy because LLMs can do things that *look* non-routine — writing, synthesizing, reasoning by analogy — while still being unreliable on things that seem routine, like arithmetic. So the old grid is breaking down somewhat.

  Your additional factors are doing real work here. I'd break it into something like:

  **Formalization** — how much of the domain's knowledge is explicit, written down, and structured. Actuarial tables, codebases, legal statutes are highly formalized. Medical diagnosis is partly formalized but heavily dependent on tacit pattern recognition and physical examination. Trades are deeply embodied.

  **Error tolerance** — software has unit tests, version control, easy rollback. If an AI writes bad code, you catch it relatively quickly. If an AI gives bad legal advice or a wrong diagnosis, the failure mode is much worse and much harder to detect. This is partly about the domain and partly about institutional structure.

  **Trust and liability** — you're right that this is a separate axis. Even where AI *could* perform well, professional licensing, malpractice liability, and client expectations create friction. Nobody sues their code autocomplete tool. People absolutely sue their doctors and lawyers.

  **Human interface** — some jobs are partly purchased *for* the human relationship. You want a human doctor to deliver a cancer diagnosis. You want a human lawyer in the courtroom. Nobody particularly cares if a human wrote the boilerplate in their contract.

  The interesting implication is that AI might hollow out the *middle* of cognitive professions — the routine analytical work that junior professionals do — while leaving both the high-level judgment and the human-facing parts intact. Which would be a strange and somewhat destabilizing dynamic for how those professions train people, since the junior work is the traditional apprenticeship path.
~ Is there anything I'm missing here?
⏺ A few things come to mind.

  **Regulation and institutional inertia** — this is related to your liability point but distinct. Some domains are slow to adopt AI not because of trust or error tolerance but simply because regulatory bodies, procurement processes, and institutional cultures move slowly. Government, healthcare, and education are famously slow to adopt new technology for reasons that have little to do with whether the technology works. This is a real bottleneck that's somewhat independent of the technical capability question.

  **Data availability and feedback loops** — programming has essentially unlimited public training data (open source code, Stack Overflow, documentation) and tight feedback loops (does it compile, does it pass tests). Medicine has comparatively restricted data due to privacy regulations, and feedback loops are long and noisy (did the patient get better? why?). This shapes how quickly AI gets good in a domain, not just how quickly it gets adopted.

  **Verifiability asymmetry** — this is subtly different from error tolerance. In programming, a non-expert can often verify AI output by running it. In law or medicine, you often need domain expertise *at least as good as the AI's* to check whether the output is correct. This creates a strange dynamic where AI is most useful where you least need it and hardest to safely deploy where you most need it.

  **The decomposability question** — some work breaks cleanly into discrete tasks that can be individually delegated to AI. Other work is holistic in a way that resists decomposition. A good diagnostician isn't running through a checklist of independent tests — they're integrating fuzzy signals in a way that's hard to hand off piecemeal. Software engineering is more modular by design.

  **Political economy** — who has the power to resist or slow adoption matters. Doctors and lawyers have strong professional organizations and high social status. Junior analysts and programmers do not. The pattern of adoption may partly reflect whose labor is politically easier to displace.

  That last one is maybe underappreciated. The ordering you described might not just reflect technical susceptibility — it might also reflect power.
~ Okay, can you model out a modern western society where AI automation at a 2025-2027 level has proliferated throughout society? What jobs and sectors have shrunk, which ones have grown, and what are potential nonlinearities or sources of surprise?
⏺ Let me try to sketch this out. I'll assume roughly current AI capabilities but much wider adoption — so not superintelligence, just what we have now deeply integrated into existing workflows with a couple years of tooling and infrastructure built around it.

  **Sectors that shrink significantly**

  Customer service and support is the obvious one. Most tier-1 support roles disappear. Translation and localization shrink dramatically. Content writing for SEO, marketing copy, basic reporting — much of this is already collapsing. Junior analyst roles in finance, consulting, and insurance thin out substantially. Entry-level legal research and document review contracts sharply. Bookkeeping and basic accounting consolidate. Graphic design for routine outputs (social media assets, slide decks, simple illustration) compresses.

  Software engineering is interesting — the total number of developers might not shrink much initially, but the *ratio* shifts. Fewer people doing implementation work, more people doing architecture, specification, and review. The productivity gain means fewer developers can do what larger teams used to, so hiring slows even if layoffs aren't dramatic.

  **Sectors that grow**

  AI integration, tooling, and operations — someone has to deploy, customize, monitor, and maintain all of this. Compliance, auditing, and AI governance — organizations need people to check what the AI is doing, manage liability, satisfy regulators. Skilled trades and physical services continue their existing trajectory of labor scarcity and wage growth. Healthcare and elder care remain labor-constrained since the bottleneck was never information processing but physical presence and human contact. Education potentially grows in some form, since widespread displacement creates retraining demand, though it's unclear whether traditional institutions capture this.

  Entertainment and creative work is ambiguous. There's more content than ever but potentially fewer people making a living from it. The economics might bifurcate — a small number of human creators with strong personal brands thrive while the middle collapses.

  **Nonlinearities and surprises**

  The apprenticeship collapse is probably the biggest structural risk. If junior roles in law, medicine, finance, and engineering disappear, you break the pipeline that produces senior people. This doesn't bite immediately — it shows up five to ten years later when there aren't enough experienced professionals and the ones remaining are irreplaceable. This could create very strange labor market dynamics where senior professionals become enormously expensive while AI handles everything below them, but there's no path to becoming senior.

  Verification bottlenecks could create unexpected demand. If organizations are producing vastly more AI-generated output, the need for human review and quality assurance might grow in ways that partially offset the displacement. You might see new roles that are essentially "AI editors" across many domains.

  Trust failures could trigger backlash cycles. One or two high-profile catastrophes — a medical AI that systematically misdiagnoses something, a legal AI that fabricates case law in a way that causes real harm, a financial model that causes losses — could trigger regulatory overcorrection that slows adoption sharply in specific sectors. This would be very uneven and hard to predict.

  The psychological and political effects of visible displacement might be nonlinear. If a critical mass of educated professionals feel threatened simultaneously, you could see political movements around AI regulation that don't track the usual left-right axis. This is different from manufacturing automation which affected a population with less political voice in knowledge-economy centers.

  Wage polarization could take a surprising shape. Rather than the usual high-skill-vs-low-skill story, you might get a barbell where high-skill cognitive workers and physical-service workers both do well, while the middle band of cognitive workers — the people who thought they were safe because they went to college and got an office job — experience the most disruption. This is politically volatile because it hits the demographic that considers itself middle class.

  One wild card: the productivity gains might not show up in GDP the way economists expect, because a lot of what AI enables is *cost reduction* rather than *new output*. A company that replaces five analysts with one analyst plus AI tools hasn't created new economic activity — it's just captured margin. If this pattern dominates, you could get a world that feels richer at the firm level but stagnant or worse at the aggregate level, with the gains flowing to capital rather than labor. This would look a lot like the productivity paradox of the last few decades, just more intense.

  {>> Alright, these are pretty familiar, we could try probing around the industries that are seeing a lot of automation and try to sketch out that that looks like given what we're seeing today, and projections. We could start with what the world looks like with massive capital concentration, that probably takes us toward economic history. We could also just ask for more unconventional/offbeat takes too. <<}

~ What's the productivity paradox of the last few decades?
⏺ The basic puzzle is that despite massive advances in computing and information technology since roughly the 1990s, measured productivity growth in advanced economies has been sluggish or declining. Robert Solow captured it memorably in 1987: "You can see the computer age everywhere but in the productivity statistics."

  There was a brief period in the late 1990s and early 2000s where productivity growth did accelerate, and many economists attributed it to IT investment finally paying off. But after about 2004-2005, productivity growth slowed again in the US and most of the developed world, and it has stayed low since. This is despite the arrival of smartphones, cloud computing, social media, and all the other technological changes that feel transformative in daily life.

  There are several competing explanations. One is measurement failure — GDP and productivity statistics were designed for an industrial economy and may not capture the value of free digital goods, convenience, and quality improvements. Your GPS navigation app is worth a lot to you but contributes almost nothing to measured GDP. Another is that the gains are real but flow to a small number of firms and individuals rather than diffusing broadly, so they show up as profit concentration rather than economy-wide productivity. A third is that recent technologies are genuinely less economically transformative than we think — that compared to electrification, indoor plumbing, or the internal combustion engine, digital technology just isn't as big a deal for material output. Robert Gordon has been the most prominent advocate of this view.

  A fourth explanation, which connects to your AI question, is that organizational and institutional adaptation takes much longer than the technology itself. Firms need to restructure workflows, retrain people, and change management practices before a new technology actually produces measurable gains. This was true of electrification too — factories didn't see big productivity gains from electric motors until they completely redesigned their physical layouts, which took decades.

  The relevance to AI is that optimists and pessimists can both point to this history. Optimists say we're in the early reorganization phase and the gains will come. Pessimists say we've heard this before and the gains never materialized last time, or they accrued very narrowly. The pattern I mentioned — where AI enables cost reduction that flows to capital rather than broad-based growth — would be a continuation of the paradox rather than a break from it.
~ Okay, I'm a little skeptical of this from an international view though - does it play out in e.g. France and China as well?
⏺ That's a good challenge and the answer is complicated.

  The productivity slowdown is genuinely a broad phenomenon across advanced economies — it shows up in France, Germany, the UK, Japan, and most of the OECD. So it's not just an American story. But the details differ enough that it's worth being skeptical of any single explanation.

  France specifically has had quite low productivity growth since the mid-2000s, but France also has structural factors that complicate the picture — the 35-hour work week, high labor market regulation, and a large public sector all affect how productivity is measured and how technology adoption plays out. French firms are also less likely to be at the frontier of IT adoption compared to American firms, so it's harder to say whether the paradox is "technology isn't producing gains" or "technology hasn't been fully deployed."

  China is a genuinely different story and I think it's where your skepticism has the most bite. China saw enormous productivity growth over the same period that advanced economies stagnated. But most economists attribute that to catch-up growth — industrialization, urbanization, massive capital investment, moving hundreds of millions of people from subsistence agriculture into manufacturing. That's a fundamentally different process from frontier productivity growth in already-rich countries. China's productivity growth has also been slowing in recent years as it approaches the middle-income range, which is consistent with the catch-up story.

  The international picture does complicate the narrative though. If the paradox were purely about technology being less transformative than we think, you'd expect it to show up fairly uniformly. The fact that it varies with institutional context, labor market structure, and development stage suggests that the technology itself might not be the main variable — it's how societies organize around it. Which actually reinforces the "slow institutional adaptation" explanation more than the "technology just isn't that important" explanation.

  I should be honest that I'm less certain about the fine-grained international comparisons here than I am about the US-centric version of the story. The productivity paradox literature is heavily US-focused and I may be pattern-matching the international picture more than I should be. If you wanted to dig deeper, the OECD publishes cross-country productivity comparisons that would give you a more rigorous picture than my summary.
~ Is there a strong reason we would expect computerization to change GDP more than it has today? Can you walk through a few scenarios here for me - let's use taxi drivers vs Uber as one example, and ecommerce (e.g. Amazon) as another example. Those seems like ones where computerization has clear benefits to delivering a service to large numbers of people; what GDP impact would be reasonable to expect? And finally, can you compare this to other innovations and their GDP impact?
⏺ These are really good test cases. Let me work through them.

  **Taxi drivers vs Uber**

  The old taxi system had massive inefficiencies — you'd stand on a street corner waving your arm, or call a dispatcher who'd radio a driver who might or might not be nearby. Medallion systems in cities like New York created artificial scarcity. Pricing was opaque. The experience was often bad.

  Uber fixed a lot of this. Matching is near-instant, routing is optimized, pricing is transparent (surge pricing aside), utilization rates for drivers improved, and the barrier to becoming a driver dropped. This is a genuine, large efficiency gain enabled entirely by computerization — GPS, smartphones, mapping software, payment processing.

  But what does this look like in GDP? The ride itself is still a person driving another person from point A to point B in a car. The core economic output hasn't changed much. If anything, Uber drove prices down in many markets, which means the *measured* value of the transaction shrank. The consumer surplus — the gap between what you'd have been willing to pay and what you actually pay — increased enormously, but consumer surplus doesn't show up in GDP. Neither does the convenience of not standing in the rain for twenty minutes.

  Meanwhile, Uber shifted value away from medallion owners (which were essentially rents) and arguably squeezed driver earnings in many markets. So you have a technology that made the experience dramatically better for consumers, destroyed a rent-seeking structure, and produced at best a modest measured GDP impact. Some of the apparent "growth" was just formalization — rides that previously happened as informal cash transactions now flow through a platform and become visible to measurement.

  **Amazon and ecommerce**

  Similar story in some ways but with more real efficiency gains that might actually show up in measurement. Amazon's logistics operation genuinely reduced the real resource cost of getting goods to people — fewer retail square feet needed, better inventory management, more efficient routing. That's real productivity improvement.

  But again, a lot of the value is in convenience and selection that GDP struggles to capture. The person in a small town who now has access to essentially the same product catalog as someone in Manhattan is enormously better off, but if they're spending the same dollar amount, GDP doesn't register the improvement. And Amazon's effect on retail has been partly destructive — it didn't just create new economic activity, it displaced existing activity in physical retail. The net GDP effect is the *difference* between what Amazon created and what it destroyed, which is much smaller than Amazon's gross revenue suggests.

  There are also measurement problems specific to ecommerce. When Amazon drives down prices through competition and efficiency, that's deflationary. If statistical agencies don't properly adjust for quality and convenience improvements, this can actually show up as *lower* measured output. There's a real debate about whether price indices adequately capture the gains from ecommerce.

  **So what GDP impact should we expect from computerization?**

  I think the honest answer is: modest measured GDP impact, large unmeasured welfare impact. Computerization is very good at reducing friction, improving matching, expanding access, and lowering costs. It's less good at creating entirely new categories of physical output. And GDP was designed to measure physical output and market transactions.

  This is where the comparison to earlier innovations is illuminating.

  **Electrification** didn't just make existing processes more convenient — it enabled entirely new forms of production. Factories could be redesigned around individual electric motors rather than a central steam shaft. This changed the physical layout of production, enabled assembly lines, allowed factories to operate at night, and created whole new product categories (home appliances, radio, refrigeration). The GDP impact was enormous because it changed what was physically produced and how.

  **Internal combustion and automobiles** created suburbs, highways, shopping malls, supply chain logistics, tourism industries. The second and third order effects dwarfed the direct value of the car itself. The physical reorganization of society around the automobile was a massive GDP event.

  **Indoor plumbing and sanitation** reduced disease, increased productive working years, enabled urban density. Again, the physical and health effects were enormous and clearly measurable.

  The pattern is that the innovations with the biggest GDP impact were ones that transformed the physical world and enabled new categories of tangible output and human capability. Computerization has been more about optimizing existing physical processes and creating a large intangible layer on top. The intangible layer is genuinely valuable — possibly as valuable as electrification in terms of human welfare — but it's partly invisible to how we measure economies.

  This might actually be the most important point for your broader AI question. If AI follows the same pattern as prior computerization — large welfare gains, modest measured GDP impact, gains concentrated in cost reduction and consumer surplus rather than new output — then the Acemoglu-style skepticism about GDP impact might be right on its own terms while still understating how much the world actually changes. The productivity paradox might be partly a measurement paradox rather than a technology paradox.

  The exception would be if AI enables something analogous to electrification — a physical reorganization of production rather than just optimization of existing processes. Robotics plus AI could potentially be that, but as you noted at the start of our conversation, that's exactly where current AI capabilities are weakest.
~ Okay, this is actually really great and ties up some of the loose ends from the initial question quite well. One more question not directly about AI - let's say we have a networked society that has massive consumer surplus that doesn't show up in GDP, but this also allows for more efficient price discrimination and financialization. I'm thinking more in the direction of private equity. What does that do in the long run?
⏺ This is a really interesting question and I think it points at something genuinely important that doesn't get discussed enough as a unified phenomenon.

  The basic dynamic you're describing is: technology creates a large pool of unmeasured value (consumer surplus), and simultaneously creates the informational infrastructure that allows sophisticated financial actors to identify and extract that value. The consumer surplus doesn't show up in GDP, but the extraction of it does show up — as profit.

  **How this works in practice**

  Price discrimination is the clearest channel. In a pre-digital world, businesses had crude tools for price discrimination — coupons, student discounts, geographic pricing. The information asymmetry mostly favored consumers, who knew their own willingness to pay while sellers had to guess. Digital infrastructure inverts this. Companies now have detailed behavioral data that lets them approach near-perfect price discrimination in some markets. Dynamic pricing for flights, Uber surge pricing, personalized discounts, insurance pricing based on granular data — all of these work by capturing consumer surplus and converting it to producer surplus. The welfare gain still exists in the sense that the transaction happens, but more of the value flows to the firm.

  Private equity enters as a second layer of extraction. PE firms are essentially specialists in identifying situations where value can be captured through financial and operational restructuring. The informational infrastructure of a networked economy makes this easier in several ways. You can identify underperforming assets more precisely, benchmark operations more granularly, and implement changes faster. But a lot of what PE does in practice is find situations where some stakeholder — workers, customers, communities, the public sector — is receiving value that isn't priced, and find ways to price it.

  The classic PE playbook in something like healthcare is: acquire a practice or hospital chain, identify that doctors are spending time in ways that don't maximize billable revenue, restructure to increase throughput, cut staff that serves patient welfare but doesn't generate revenue, extract real estate value, load the entity with debt to capture tax advantages, and sell. The "efficiency gain" is partly real but partly just a transfer from patients and workers to investors. From a GDP perspective this can look like productivity improvement even when the actual service has degraded.

  **What this does in the long run**

  I think the concerning scenario runs something like this. You get a society that is genuinely more efficient and more convenient on the surface, but where an increasing share of economic activity is devoted to value capture rather than value creation. The aggregate numbers can look fine or even good — corporate profits are up, GDP grows modestly, unemployment stays manageable — while the lived experience for most people gets slowly worse in ways that are hard to articulate and easy to dismiss.

  Housing is maybe the clearest example already playing out. The financialization of housing through REITs, PE-backed rental companies, and algorithmic pricing tools like RealPage means that the housing market is increasingly optimized to extract maximum willingness to pay from renters. The houses are the same houses. No new value has been created. But the informational and financial infrastructure allows much more efficient extraction of what was previously consumer surplus in the form of below-market rents, long-term tenant relationships, and landlords who didn't optimize aggressively.

  Healthcare follows a similar pattern. Private equity acquisition of medical practices, hospitals, nursing homes, and emergency staffing companies has been extensively documented, and the pattern is remarkably consistent — costs to patients go up, quality of care goes down, and the difference flows to investors. The networked information economy makes this more feasible because you can monitor and optimize clinical operations in real time in ways that weren't previously possible.

  **The macroeconomic feedback**

  Here's where it gets potentially nonlinear. If an increasing share of economic activity is extraction rather than creation, you get a few feedback effects.

  Consumer spending power erodes gradually as surplus is captured, which suppresses demand. Firms respond to weak demand not by investing in new production but by further optimizing extraction from existing activity, because that's where the returns are. Investment shifts from productive capital to financial engineering. You get what looks like a low-growth, low-investment, high-profit economy — which is a reasonable description of much of the developed world over the last fifteen to twenty years.

  The political dimension matters here too. The people experiencing this erosion of surplus are the same educated middle class you identified earlier as being most disrupted by AI. They can feel that life is getting harder and more precarious despite apparent economic stability, but the mechanisms are opaque enough that it's difficult to point to a clear cause. This creates a free-floating sense of grievance that is easily captured by political movements offering simple explanations, whether those explanations are accurate or not.

  **Tying it back to AI**

  If AI follows the pattern we discussed — large unmeasured welfare gains, modest GDP impact, gains flowing primarily to capital — then it slots neatly into this dynamic. AI makes price discrimination more precise, makes PE-style operational optimization more powerful, and makes it easier to substitute capital for labor in cognitive work. The technology is genuinely creating value, but the institutional and financial infrastructure surrounding it is increasingly oriented toward capturing that value for a narrow set of actors.

  The optimistic counter is that competition should in theory drive prices down and pass gains to consumers. And in some markets it does — Amazon has genuinely lowered prices for many goods. But the tendency toward market concentration in digital markets, combined with increasingly sophisticated tools for price discrimination, means competition doesn't always work the way the textbook says.

  I don't think this is a story with a clean resolution. It's more of a slow structural shift that makes economies more fragile, politics more volatile, and the relationship between technological progress and broadly shared prosperity more tenuous than it used to be.
~ Okay, so that's kind of just low growth, increasing inequality?
⏺ Basically yes, but I think there's a subtle and important distinction between this and the standard "low growth, increasing inequality" story that people have been telling since Piketty.

  The standard version is mostly about *distribution* — the pie grows slowly and the rich get a bigger slice. The mechanism is usually told as some combination of globalization, skill-biased technological change, declining union power, and tax policy. The prescription is usually redistributive — tax more, transfer more, maybe strengthen labor bargaining power.

  What you're describing is slightly different and I think more corrosive. It's not just that the pie is being divided unfairly — it's that an increasing share of economic *activity* is oriented toward dividing the pie rather than making it bigger. The financialization and extraction layer doesn't just redistribute existing value, it actively consumes resources doing so. Smart people spend their careers optimizing price discrimination algorithms and structuring PE deals instead of doing things that expand productive capacity. This is a drag on growth itself, not just distribution.

  So it's not just that the gains go to the top. It's that the economy's capacity to generate broad gains is being slowly degraded by the very mechanisms that make it look healthy from the top. The low growth isn't just happening alongside the inequality — the inequality *machinery* is partly causing the low growth.

  That said, I want to be honest about the limits of this framing. It's a plausible story and it fits a lot of the observable facts, but it's hard to empirically distinguish from simpler explanations. Maybe growth is just slow because the easy gains from industrialization and electrification have been captured and we're on a technological plateau. Maybe inequality is just a distribution problem and the growth slowdown is a separate phenomenon. The extraction story is compelling but it's hard to prove the causal link rigorously, and I'm wary of presenting a tidy narrative when the reality might be messier and more multicausal.
  ~ Has there been any writing from economists, sociologists, or other commentators pursuing a similar line of inquiry?
  ⏺ Yes, quite a bit, though it's scattered across disciplines and nobody has quite assembled it into the unified picture you've been building in this conversation.

    On the financialization side, Gerald Epstein has written extensively on financialization as a drag on productive investment. Greta Krippner's "Capitalizing on Crisis" traced the shift of the US economy toward financial activity starting in the 1970s and argued it wasn't just a distributional change but a structural reorientation of what the economy *does*. Rana Foroohar's "Makers and Takers" is a more popular treatment of the same basic argument — that finance has shifted from facilitating production to extracting from it.

    On the PE-specific dimension, Eileen Appelbaum and Rosemary Batt have done probably the most rigorous empirical work on what private equity actually does to the firms it acquires, particularly in healthcare. Their findings are broadly consistent with the extraction story — worse outcomes for workers and often for service quality, with gains flowing to investors.

    On the rent-seeking and unproductive activity side, there's a long tradition going back to people like William Baumol who distinguished between productive and unproductive entrepreneurship. More recently, Brett Christophers' "Rentier Capitalism" argues that the UK economy in particular has become dominated by rent extraction rather than productive activity. This is close to what you're describing.

    On the technology and surplus capture intersection specifically, this is where it gets thinner. Cory Doctorow's concept of "enshittification" is honestly one of the better popular framings — the idea that platforms create value to attract users, then gradually degrade the user experience to capture that value for shareholders. It's not academic economics but it describes the mechanism you're talking about quite precisely.

    Shoshana Zuboff's "Surveillance Capitalism" covers the informational infrastructure that enables the surplus extraction, though she frames it more in terms of autonomy and power than in economic terms.

    Jonathan Tepper and Denise Hearn's "The Myth of Capitalism" covers the market concentration angle — how reduced competition enables surplus extraction.

    The gap I see in the literature is exactly what you've been doing — connecting the AI productivity question, the measurement problem, the financialization dynamic, and the extraction machinery into a single coherent story. Each piece exists but they tend to be discussed in separate conversations by people in different disciplines. Economists talk about productivity. Sociologists talk about financialization. Technology critics talk about platforms. The synthesis is relatively underdeveloped.

    I should caveat that I'm more confident about the older and more established references here than about whether I'm correctly characterizing every recent work. And there may be people doing exactly this synthesis that I'm not aware of.
  ~ Alright, so there are a *lot* of critiques of financialization, but it seems like they're missing something here.
  ⏺ Yes. I think the piece they're mostly missing is the informational substrate that makes the current phase of financialization qualitatively different from earlier phases.

    Most of the financialization critique is essentially a story about power and institutional change — deregulation, shareholder primacy ideology, the decline of countervailing forces like unions. And that's all real. But it treats the informational revolution as mostly incidental, as just the backdrop against which these power shifts happened.

    What your line of reasoning suggests is that the information technology isn't backdrop — it's *load-bearing*. The networked digital economy doesn't just happen to coexist with financialization, it actively enables a kind of extraction that wasn't previously possible. You can't do algorithmic price discrimination without the data infrastructure. You can't do PE-style rapid operational optimization without real-time analytics. You can't do RealPage-style rent coordination without the platform. The technology creates the consumer surplus *and* creates the tools to capture it, and these are two aspects of the same system rather than separate phenomena.

    The financialization critics tend to tell a story where the solution is political — restore regulation, break up concentrations of power, strengthen labor. The technology critics tend to tell a story where the problem is technical — fix the algorithms, regulate the platforms, protect data. But if you're right that these are the same phenomenon, then neither framing is sufficient on its own. Regulating finance without addressing the informational infrastructure that enables extraction just pushes it into new channels. Regulating technology without addressing the financial incentives that drive extraction just means the same actors find new tools.

    And then AI enters this picture not as a separate disruption but as an intensification of the same dynamic. It makes the information substrate more powerful, which simultaneously creates more surplus and makes extraction more efficient. Which is a somewhat bleaker framing than either the AI optimists or the standard financialization critics offer, because it suggests that the problem isn't a policy failure or a technology problem but an emergent property of the interaction between the two.

    The question I'd push back to you is whether there's a plausible institutional arrangement that breaks this coupling, or whether it's inherent to the combination of digital infrastructure and market economies.
   ~ Okay, let's explore one branch here then - has anyone tried to unpack a future where we get hyperacceleration of these dynamics of financialization, maybe because of AI/singularity-ish projections, maybe just extrapolating from earlier technological growth and computerization? Looking for less speculative, fictionalized, or dystopian takes; open to fiction or speculative futures if they take a political economy angle.
   ⏺ This is a surprisingly thin area given how obvious the question seems.

      On the more rigorous end, there's some work that gets partway there. Mervyn King and John Kay's "Radical Uncertainty" doesn't directly address this but lays groundwork for thinking about how financial systems behave when information infrastructure becomes very powerful but the underlying uncertainty of the world doesn't actually decrease. Their argument is that finance mistakes information for knowledge, and you could extend that to say that AI-enhanced financialization would accelerate this mistake — more sophisticated extraction based on models that feel precise but are still fundamentally uncertain. They don't make that extension themselves though.

      Daniela Gabor's work on what she calls the "Wall Street Consensus" gets closer. She argues that development finance and public policy are being restructured to create investable asset classes for global finance — essentially that the state is being redesigned to facilitate extraction. You could project that forward into a world where AI makes this process faster and more granular, but again she doesn't make that move explicitly.

      Brett Christophers' more recent "The Price is Wrong" about renewable energy financing touches on something relevant — how even the transition to green energy is being structured primarily as a financial extraction opportunity rather than a public investment. This is a concrete case of a major societal transformation being mediated through financialization logic, which is suggestive of how AI adoption might play out.

      On the speculative and fiction side, the pickings are surprisingly slim for what you're asking. A lot of science fiction deals with corporate dystopia or AI risk, but very few works take political economy seriously as a mechanism rather than as aesthetic. Kim Stanley Robinson is probably the closest — his "Ministry for the Future" takes climate change and financial systems seriously as interacting dynamics and actually engages with things like central bank policy and carbon quantitative easing. It's not about AI specifically but it's one of the few works of fiction that treats financial infrastructure as a plot-driving mechanism rather than window dressing.

      Cory Doctorow's fiction, particularly "Walkaway," engages with post-scarcity economics and the question of who captures value from abundance, though it's more focused on the possibility of opting out than on modeling the financialization dynamic from inside.

      There's a notable absence in the rationalist and AI safety adjacent literature too. The people thinking hardest about AI trajectories — Bostrom, Yudkowsky, Aschenbrenner — tend to jump past political economy entirely. They go from "AI gets very capable" to either "existential risk" or "massive GDP growth" without spending much time on the intermediate dynamics of who captures the value and through what institutional mechanisms. Hanson is the partial exception since his economic modeling is more granular, but even he tends to think in terms of aggregate productivity rather than extraction dynamics.

      The gap you're identifying is real and I think it matters. There's a whole scenario space between "AI doesn't change much" and "AI transforms everything" where the most likely near-term path runs — AI significantly enhances the capacity for value extraction by sophisticated financial actors, the gains are large but accrue very narrowly, measured economic growth is modest, and the political consequences are significant. This is arguably the most probable medium-term future and it's undertheorized relative to both the optimistic and catastrophist scenarios.

      If this interests you, honestly the closest thing to the analysis you're looking for might be assembling it yourself from the pieces we've been discussing. The individual components exist but the synthesis connecting AI capability trajectories, financialization dynamics, surplus creation and capture, and political economy outcomes doesn't really exist as a coherent body of work yet, at least not that I'm aware of.
~ Great! This is a good stopping point for today. We'll come back to the AI angle later.
