# C++ 컴파일러 지정
CXX = g++

# 컴파일 옵션 (모든 경고, 추가 경고, 디버깅 정보, C++11 표준)
CXXFLAGS = -Wall -Wextra -g -std=c++11

# 링커 옵션 (pcap 라이브러리 링크)
LDFLAGS = -lpcap

# 최종 실행 파일 이름
TARGET = send-arp

# 모든 .cpp 소스 파일 목록을 자동으로 찾음
SRCS = $(wildcard *.cpp)

# 소스 파일 목록으로부터 object 파일(.o) 목록을 생성
OBJS = $(SRCS:.cpp=.o)

# 기본 규칙: 'make'만 입력하면 all이 실행됨
all: $(TARGET)

# 최종 실행 파일 생성 규칙
# object 파일들을 링크하여 최종 실행 파일을 만듦
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# object 파일 생성 규칙
# .cpp 파일로부터 .o 파일을 만듦 (-c 옵션: 컴파일만 수행)
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 정리 규칙: 'make clean' 실행 시 생성된 파일 삭제
clean:
	rm -f $(TARGET) $(OBJS)

# 가상 목표 지정 (실제 파일이 아님을 명시)
.PHONY: all clean