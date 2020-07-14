OBJS=monitor.o
TARGET=monitor
RM=rm -f

LIBS= -lpthread
TEST_TARGET=test
TEST_OBJS= test.o

all:$(TEST_TARGET) $(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LIBS)

$(OBJS):%o:%c
	$(CC) -c  $< -o $@

$(TEST_TARGET):$(TEST_OBJS)
	$(CC) -o $(TEST_TARGET) $(TEST_OBJS) $(LIBS)
##	$(CC) -o $@ $< $(CFLAGS)

$(TEST_OBJS):%o:%c
	$(CC) -c $< -o $@

clean:
	$(RM) $(TARGET) $(OBJS)
	$(RM) $(TEST_TARGET) $(TEST_OBJS)
