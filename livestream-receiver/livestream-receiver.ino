#define N 192
#pragma pack(1)
struct point {
  uint16_t x; uint8_t y;
} point_buffer[N];

#include "tucn.h"

// python -c 'print([(((Y&0b11)<<20) | ((Y&0b1100)<<14) | ((Y&0b10000)<<15) | ((Y&0b1100000)<<3) | ((Y&0b10000000)<<4)) for Y in range(256)])'
const uint32_t porta_bitmap_lut[256] = {0, 1048576, 2097152, 3145728, 65536, 1114112, 2162688, 3211264, 131072, 1179648, 2228224, 3276800, 196608, 1245184, 2293760, 3342336, 524288, 1572864, 2621440, 3670016, 589824, 1638400, 2686976, 3735552, 655360, 1703936, 2752512, 3801088, 720896, 1769472, 2818048, 3866624, 256, 1048832, 2097408, 3145984, 65792, 1114368, 2162944, 3211520, 131328, 1179904, 2228480, 3277056, 196864, 1245440, 2294016, 3342592, 524544, 1573120, 2621696, 3670272, 590080, 1638656, 2687232, 3735808, 655616, 1704192, 2752768, 3801344, 721152, 1769728, 2818304, 3866880, 512, 1049088, 2097664, 3146240, 66048, 1114624, 2163200, 3211776, 131584, 1180160, 2228736, 3277312, 197120, 1245696, 2294272, 3342848, 524800, 1573376, 2621952, 3670528, 590336, 1638912, 2687488, 3736064, 655872, 1704448, 2753024, 3801600, 721408, 1769984, 2818560, 3867136, 768, 1049344, 2097920, 3146496, 66304, 1114880, 2163456, 3212032, 131840, 1180416, 2228992, 3277568, 197376, 1245952, 2294528, 3343104, 525056, 1573632, 2622208, 3670784, 590592, 1639168, 2687744, 3736320, 656128, 1704704, 2753280, 3801856, 721664, 1770240, 2818816, 3867392, 2048, 1050624, 2099200, 3147776, 67584, 1116160, 2164736, 3213312, 133120, 1181696, 2230272, 3278848, 198656, 1247232, 2295808, 3344384, 526336, 1574912, 2623488, 3672064, 591872, 1640448, 2689024, 3737600, 657408, 1705984, 2754560, 3803136, 722944, 1771520, 2820096, 3868672, 2304, 1050880, 2099456, 3148032, 67840, 1116416, 2164992, 3213568, 133376, 1181952, 2230528, 3279104, 198912, 1247488, 2296064, 3344640, 526592, 1575168, 2623744, 3672320, 592128, 1640704, 2689280, 3737856, 657664, 1706240, 2754816, 3803392, 723200, 1771776, 2820352, 3868928, 2560, 1051136, 2099712, 3148288, 68096, 1116672, 2165248, 3213824, 133632, 1182208, 2230784, 3279360, 199168, 1247744, 2296320, 3344896, 526848, 1575424, 2624000, 3672576, 592384, 1640960, 2689536, 3738112, 657920, 1706496, 2755072, 3803648, 723456, 1772032, 2820608, 3869184, 2816, 1051392, 2099968, 3148544, 68352, 1116928, 2165504, 3214080, 133888, 1182464, 2231040, 3279616, 199424, 1248000, 2296576, 3345152, 527104, 1575680, 2624256, 3672832, 592640, 1641216, 2689792, 3738368, 658176, 1706752, 2755328, 3803904, 723712, 1772288, 2820864, 3869440};

inline void draw_point(uint16_t X, uint8_t Y) {
  analogWrite(A0, X);
  PORT->Group[PORTA].OUT.reg = porta_bitmap_lut[Y];
}

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

  Serial.begin(2000000);
  Serial.setTimeout(1);

  long last_hello = millis();
  do {
    for (int i = 0; i < num_points; i++) {
      draw_point(points[i].x, points[i].y);
    }
    if (millis() - last_hello > 500) {
      Serial.println("Hello?");
      last_hello = millis();
    }
  } while (Serial.read() != '!');
  Serial.println("Hello!");
  Serial.println(N);

  const long micros_per_frame = 1000000 * N / 192000;

  // loop() with no overhead
  long wait = 100;
  while (1) {
    const long started_receiving = micros();
    unsigned int received = 0, remaining = sizeof(point_buffer);
    while (remaining > 0) {
      const auto received_now = Serial.readBytes((char*) point_buffer + received, remaining);
      received += received_now;
      remaining -= received_now;
    }
    const long ended_receiving = micros();
    for (int i = 0; i < N; i++) {
      draw_point(point_buffer[i].x, point_buffer[i].y);
      for (int j = 0; j < wait; j++);
    }
    const long ended_drawing = micros();

    //    i want ended_drawing - started_receiving = micros_per_frame
    //    i can change ended_drawing - ended_receiving by wait
    const long draw_should_be_this_longer = micros_per_frame - ended_drawing + started_receiving;
    if (draw_should_be_this_longer > 0 && wait < 999999) wait++;
    if (draw_should_be_this_longer < 0 && wait > 1) wait--;
  }
}

void loop() {
}
