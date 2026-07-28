package main

const (
        opHALT  = 0
        opPUSH  = 1
        opPUSHD = 2
        opLOADK = 3
        opADD   = 4
        opSUB   = 5
        opMUL   = 6
        opXOR   = 7
        opAND   = 8
        opOR    = 9
        opROL8  = 10
        opROR8  = 11
        opDUP   = 12
        opSWAP  = 13
        opPOP   = 14
        opSTO   = 15
        opLOD   = 16
        opJMP   = 17
        opJZ    = 18
        opRET   = 19
        opEQ    = 20
        opLENK  = 21
        opSHL   = 22
        opSHR   = 23
)

func rol8(x, n uint32) uint32 {
        n &= 7
        x &= 0xff
        return ((x << n) | (x >> (8 - n))) & 0xff
}

func runVM(code []byte, key []byte) bool {
        stack := make([]uint32, 0, 64)
        slot := make([]uint32, 96)
        push := func(v uint32) { stack = append(stack, v) }
        pop := func() uint32 {
                v := stack[len(stack)-1]
                stack = stack[:len(stack)-1]
                return v
        }

        ip := 0
        for ip < len(code) {
                op := int(code[ip])
                ip++
                switch op {
                case opHALT:
                        return false
                case opPUSH:
                        push(uint32(code[ip]))
                        ip++
                case opPUSHD:
                        v := uint32(code[ip]) | uint32(code[ip+1])<<8 | uint32(code[ip+2])<<16 | uint32(code[ip+3])<<24
                        ip += 4
                        push(v)
                case opLOADK:
                        idx := int(code[ip])
                        ip++
                        if idx >= 0 && idx < len(key) {
                                push(uint32(key[idx]))
                        } else {
                                push(0)
                        }
                case opADD:
                        b, a := pop(), pop()
                        push(a + b)
                case opSUB:
                        b, a := pop(), pop()
                        push(a - b)
                case opMUL:
                        b, a := pop(), pop()
                        push(a * b)
                case opXOR:
                        b, a := pop(), pop()
                        push(a ^ b)
                case opAND:
                        b, a := pop(), pop()
                        push(a & b)
                case opOR:
                        b, a := pop(), pop()
                        push(a | b)
                case opROL8:
                        n := uint32(code[ip])
                        ip++
                        push(rol8(pop(), n))
                case opROR8:
                        n := code[ip] & 7
                        ip++
                        a := pop() & 0xff
                        push(((a >> n) | (a << (8 - n))) & 0xff)
                case opDUP:
                        push(stack[len(stack)-1])
                case opSWAP:
                        n := len(stack)
                        stack[n-1], stack[n-2] = stack[n-2], stack[n-1]
                case opPOP:
                        pop()
                case opSTO:
                        i := code[ip]
                        ip++
                        slot[i] = pop()
                case opLOD:
                        i := code[ip]
                        ip++
                        push(slot[i])
                case opJMP:
                        rel := int(int16(uint16(code[ip]) | uint16(code[ip+1])<<8))
                        ip += 2
                        ip += rel
                case opJZ:
                        rel := int(int16(uint16(code[ip]) | uint16(code[ip+1])<<8))
                        ip += 2
                        if pop() == 0 {
                                ip += rel
                        }
                case opRET:
                        return pop() != 0
                case opEQ:
                        b, a := pop(), pop()
                        if a == b {
                                push(1)
                        } else {
                                push(0)
                        }
                case opLENK:
                        push(uint32(len(key)))
                case opSHL:
                        n := code[ip]
                        ip++
                        push(pop() << n)
                case opSHR:
                        n := code[ip]
                        ip++
                        push(pop() >> n)
                default:
                        return false
                }
        }
        return false
}
