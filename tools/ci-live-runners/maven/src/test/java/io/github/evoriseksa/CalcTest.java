package io.github.evoriseksa;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

final class CalcTest {
    @Test
    void doublesThree() {
        assertEquals(6, Calc.twice(3));
    }

    @Test
    void doublesFive() {
        assertEquals(10, Calc.twice(5));
    }
}
