struct point {
  uint16_t x; uint8_t y;
};

#include "tucn.h"

void setup() {
  pinMode(A0, OUTPUT);
  analogWriteResolution(10);

  pinMode(6, OUTPUT);
  pinMode(7, OUTPUT);
  pinMode(8, OUTPUT);
  pinMode(9, OUTPUT);
  pinMode(10, OUTPUT);
  pinMode(11, OUTPUT);
  pinMode(12, OUTPUT);
  pinMode(3, OUTPUT);
}

void loop() {
  for(int i = 0; i < num_points; i++) {
    analogWrite(A0, points[i].x);

    // write all 8 pins at once
    const long Y = points[i].y;
    PORT->Group[PORTA].OUT.reg = ((Y&0b11)<<20) | ((Y&0b1100)<<14) |
        ((Y&0b10000)<<15) | ((Y&0b1100000)<<3) | ((Y&0b10000000)<<4);

    // slow down ringing
    delayMicroseconds(3);
  }
}
