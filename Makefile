MY_PROG := br

CMN_PATH := _cmn
CMN_SRCS := KException KSocket my_basic
CMN_OBJS := $(CMN_SRCS:%=obj_cmn/%.o)
CMN_DEPS := $(CMN_SRCS:%=obj_cmn/%.d)

MY_SRCS := $(wildcard src/*.cpp)
MY_OBJS := $(MY_SRCS:src/%.cpp=obj/%.o)
MY_DEPS := $(MY_SRCS:src/%.cpp=obj/%.d)

MY_INC_PATH := \
  -I /home/docker_shared/boost/boost_1_87_0\
  -I $(CMN_PATH)

# -g : デバッグ用ビルドを実行
# -rdynamic : 共有ファイルからデバッグ用シンボル名を出力
# -ldl, -lbacktrace : stacktrace 取得のため（OBJ ファイルの後に書くこと）
MY_OPTS := -std=c++20 -g -Wall -Wno-format-security
MY_LINK_OPTS := -rdynamic -ldl -lbacktrace
#MY_LINK_OPTS := -rdynamic -ldl -lbacktrace -lpthread


# -------------------------------------------------
build: $(MY_OBJS) $(CMN_OBJS)
	rm -f $(MY_PROG)
	g++-13 $(MY_OPTS) $^ $(MY_LINK_OPTS) -o $(MY_PROG)

# -H : プリコンパイル済みヘッダを利用するオプション
obj/%.o: src/%.cpp
	g++-13 -MMD $(MY_OPTS) $(MY_INC_PATH) -c $< -o $@
#	g++-13 -MMD $(MY_OPTS) $(MY_INC_PATH) -H -c $< -o $@

obj_cmn/%.o: $(CMN_PATH)/%.cpp
	g++-13 -MMD $(MY_OPTS) $(MY_INC_PATH) -c $< -o $@
#	g++-13 -MMD $(MY_OPTS) $(MY_INC_PATH) -H -c $< -o $@


# -------------------------------------------------
.PHONY: clean
clean:
	@rm -f $(MY_PROG) obj/* obj_cmn/*

# -------------------------------------------------
#%:
#	$(eval S := src/$@.cpp)
#	$(eval O := obj/$@.o)
#	g++-13 $(MY_OPTS) -c $S -o $O

-include $(CMN_DEPS) $(MY_DEPS)
