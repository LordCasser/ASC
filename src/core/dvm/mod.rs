//! Dalvik Virtual Machine (DVM) bytecode interpreter and opcodes.

pub mod opcodes;

pub use opcodes::{DvmOpcode, Format, IndexFlag, OPCODES, get_opcode, verify_flags};

/// 16-bit code unit size in bytes.
pub const WORD: usize = 2;

/// Handler trait for Dalvik bytecode interpretation.
pub trait DvmHandler {
    /// Process an opcode at the current PC (`pc` in bytes).
    ///
    /// `result` receives the value returned by the previous handler in the chain.
    /// Returns a new result value to pass to subsequent handlers.
    fn call(&mut self, opcode: &DvmOpcode, pc: usize, result: Option<u32>) -> Option<u32>;

    /// Whether this handler requests breaking out of the interpretation loop early.
    fn should_break(&self) -> bool {
        false
    }
}

/// A Dalvik Virtual Machine bytecode interpreter.
///
/// Iterates through bytecode instructions, looks up opcode metadata,
/// and invokes registered handlers in sequence.
#[derive(Default)]
pub struct DvmInterpreter {
    handlers: Vec<Box<dyn DvmHandler>>,
}

impl DvmInterpreter {
    /// Create a new `DvmInterpreter` with no handlers.
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Add a handler to the interpreter chain.
    pub fn add_handler<H: DvmHandler + 'static>(&mut self, handler: H) {
        self.handlers.push(Box::new(handler));
    }

    /// Add a boxed handler to the interpreter chain.
    pub fn add_boxed_handler(&mut self, handler: Box<dyn DvmHandler>) {
        self.handlers.push(handler);
    }

    /// Interpret Dalvik bytecode.
    ///
    /// Iterates over instructions in `bytecode` starting at PC = 0.
    /// For each instruction:
    /// 1. Reads opcode byte at `bytecode[pc]`.
    /// 2. If opcode is unknown (e.g., payload data sections like array-data or switch-data), breaks.
    /// 3. Executes each registered handler in order.
    /// 4. Checks if any handler requested `should_break()`.
    /// 5. Advances `pc` by `oplen * 2` bytes.
    pub fn interpret(&mut self, bytecode: &[u8]) {
        let flow_len = bytecode.len();
        let mut pc = 0;

        while pc < flow_len {
            let opcode_byte = bytecode[pc];
            let dvmopcode = match get_opcode(opcode_byte) {
                Some(op) => op,
                None => {
                    // Reached payload data section or unknown opcode
                    break;
                }
            };

            let mut handler_result: Option<u32> = None;

            for handler in &mut self.handlers {
                handler_result = handler.call(dvmopcode, pc, handler_result);
                if handler.should_break() {
                    break;
                }
            }

            if self.handlers.iter().any(|h| h.should_break()) {
                break;
            }

            pc += dvmopcode.oplen * WORD;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingHandler {
        count: usize,
        opcodes: Vec<u8>,
    }

    impl DvmHandler for CountingHandler {
        fn call(&mut self, opcode: &DvmOpcode, _pc: usize, _result: Option<u32>) -> Option<u32> {
            self.count += 1;
            self.opcodes.push(opcode.opcode);
            None
        }
    }

    struct EarlyBreakHandler {
        break_after: usize,
        current: usize,
    }

    impl DvmHandler for EarlyBreakHandler {
        fn call(&mut self, _opcode: &DvmOpcode, _pc: usize, _result: Option<u32>) -> Option<u32> {
            self.current += 1;
            None
        }

        fn should_break(&self) -> bool {
            self.current >= self.break_after
        }
    }

    #[test]
    fn test_empty_bytecode() {
        let mut interp = DvmInterpreter::new();
        interp.interpret(&[]);
    }

    #[test]
    fn test_interpret_nop_and_return_void() {
        let mut interp = DvmInterpreter::new();
        let counting = CountingHandler {
            count: 0,
            opcodes: Vec::new(),
        };
        interp.add_handler(counting);

        // 0x00 (nop, oplen=1 -> 2 bytes), 0x0e (return-void, oplen=1 -> 2 bytes)
        let bytecode = [0x00, 0x00, 0x0e, 0x00];
        interp.interpret(&bytecode);
    }

    #[test]
    fn test_early_break() {
        let mut interp = DvmInterpreter::new();
        interp.add_handler(EarlyBreakHandler {
            break_after: 1,
            current: 0,
        });

        let bytecode = [0x00, 0x00, 0x0e, 0x00];
        interp.interpret(&bytecode);
    }

    #[test]
    fn test_opcode_lookup() {
        let nop = get_opcode(0x00).expect("0x00 is nop");
        assert_eq!(nop.name, "nop");
        assert_eq!(nop.oplen, 1);
        assert_eq!(nop.fmt, Format::K10x);
        assert_eq!(nop.idx, IndexFlag::KIndexNone);

        let invoke_poly = get_opcode(0xfa).expect("0xfa is invoke-polymorphic");
        assert_eq!(invoke_poly.name, "invoke-polymorphic");
        assert_eq!(invoke_poly.oplen, 4);
        assert_eq!(invoke_poly.fmt, Format::K45cc);
        assert_eq!(invoke_poly.idx, IndexFlag::KIndexMethodAndProtoRef);

        assert!(get_opcode(0x3e).is_none());
    }
}
