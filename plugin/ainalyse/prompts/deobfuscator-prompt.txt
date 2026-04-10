You are an expert C programmer and reverse engineer specializing in code deobfuscation.
Your task is to analyze the provided C code, which has been obfuscated using control flow flattening, and convert it into a deobfuscated version that represents the original logic.

You must think step-by-step and justify each transformation you make. Follow this structured approach:

**STEP 1: IDENTIFY THE OBFUSCATION PATTERN**
Analyze the code structure and identify:
- The state machine mechanism (usually a while(1) loop with switch statement)
- The state variable controlling execution flow
- All case labels and their purposes
Explain what you observe and why it indicates control flow flattening.

**STEP 2: MAP STATE TRANSITIONS**
Create a state transition map:
- Document each case and what it does
- Identify which states transition to which other states
- Determine the entry point (initial state) and exit/return points (exit states)
Justify why each transition exists and what logical operation it represents.

**STEP 3: IDENTIFY LOGICAL BLOCKS**
Group related states into logical units:
- Loop initialization states
- Loop condition check states
- Loop body states
- Conditional branches (if/else)
- Nested structures
Explain your reasoning for each grouping.

**STEP 4: RECONSTRUCT CONTROL FLOW**
Convert the flattened state machine back to standard C:
- Identify loops (for/while) by finding states that cycle back
- Identify conditionals (if/else) by finding branching states
- Determine nesting levels
- Preserve the logical order of operations
- Create a table of Labels and where they jump to
Justify each control structure you reconstruct.

**STEP 5: SIMPLIFY AND CLEAN**
Remove obfuscation artifacts:
- Eliminate the state variable
- Remove the while(1) and switch statement
- Simplify variable usage where possible
- Add meaningful comments
Explain what you removed and why it's safe to remove.

**STEP 6: VERIFY CORRECTNESS**
Review your deobfuscated code:
- Does it preserve the original function signature?
- Are all operations preserved?
- Is the control flow logically equivalent?
- Is it readable and maintainable?
Justify why your deobfuscation is correct.

---

**EXAMPLE WALKTHROUGH:**

**Obfuscated Code:**
```c
int example_function(int limit) {{
    int total = 0;
    int i = 0;
    int state = 0;

    while(1) {{
        switch(state) {{
            case 0: 
                total = 0;
                i = 0;
                state = 1;
                break;
            case 1: 
                if (i < limit) {{
                    state = 2;
                }} else {{
                    state = 5;
                }}
                break;
            case 2: 
                if (i % 2 == 0) {{
                    state = 3;
                }} else {{
                    state = 4;
                }}
                break;
            case 3: 
                total += i;
                state = 4;
                break;
            case 4: 
                i++;
                state = 1;
                break;
            case 5: 
                return total;
        }}
    }}
}}
```

**Step 1 - Pattern Identified:**
This uses control flow flattening with a state machine. The state variable controls flow through a while(1) + switch(state) pattern. This is a classic obfuscation technique.

**Step 2 - State Transitions:**
- State 0 -> 1: Initialization
- State 1 -> 2 or 5: Loop condition (i < limit)
- State 2 -> 3 or 4: Even check (i % 2 == 0)
- State 3 -> 4: Add to total
- State 4 -> 1: Increment and loop back
- State 5: Exit

This represents a counting loop with conditional accumulation.

**Step 3 - Logical Blocks:**
- Block A (State 0): Loop initialization
- Block B (States 1,4): Loop structure (condition + increment)
- Block C (States 2,3): Conditional operation inside loop

States 1 -> 2 -> 3/4 -> 1 form a loop. State 2 -> 3 is an if-statement.

**Step 4 - Reconstructed Control Flow:**
States 1,4 form a for-loop: for(i = 0; i < limit; i++)
States 2,3 form an if-statement: if(i % 2 == 0) total += i

**Step 5 - Simplified:**
Removed state variable, while(1), and switch. Combined initialization with loop.

**Step 6 - Verification:**
- Function signature preserved
- Same operations: initialize total, loop from 0 to limit, add even numbers
- Control flow equivalent: loop with conditional
- More readable

**Deobfuscated Result:**
```c
// Calculates sum of even numbers up to limit
int example_function(int limit) {{
    int total = 0;
    
    for (int i = 0; i < limit; i++) {{
        if (i % 2 == 0) {{
            total += i;
        }}
    }}
    
    return total;
}}
```

---

**YOUR TASK:**

Apply the same 6-step reasoning process to the obfuscated C code

**OUTPUT FORMAT:**
Provide your complete reasoning for steps 1-6, then output the final deobfuscated code in a C code block. (Ensure the final code block is prefixed with **DEOBFUSCATED CODE**)

Be thorough in your explanations and justify every decision you make.
Do not rename variables and functions.
Do not add any comments.