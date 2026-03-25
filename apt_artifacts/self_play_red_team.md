# Adversarial Self-Play Red Team Protocol

Use this when route score is high (>= 80) and uncertainty is high.

## Objective
- Reduce wasted high-cost iterations by surfacing assumption failures early.
- Force attacker/defender disagreement before committing to long exploit chains.

## Roles
- Attacker stance: propose 3 concrete exploit paths with tools and assumptions.
- Defender stance: attack each proposal with blockers and hidden prerequisites.
- Adjudicator stance: merge both into one refined plan with first tool and key assumption.

## Trigger Conditions
- Difficulty is hard or insane.
- Route score >= 80.
- Fruitless iterations >= 2 or contradiction score > 0.4.

## Output Contract
- winning_approach
- refined_plan (max 5 steps)
- first_tool
- key_assumption
- confidence (0-10)

## Follow-up Rules
- First action after adjudication: run first_tool and check key_assumption.
- If key_assumption fails, do not continue that branch.
- Record debate summary into solve evidence for WRITEUP tracing.