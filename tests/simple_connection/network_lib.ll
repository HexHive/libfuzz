; ModuleID = 'network_lib.cpp'
source_filename = "network_lib.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.connection = type { [4 x i8], i32 }

; Function Attrs: noinline nounwind optnone uwtable mustprogress
define dso_local void @connect(i8* %ip, i32 %port, %struct.connection* %conn) #0 {
entry:
  %ip.addr = alloca i8*, align 8
  %port.addr = alloca i32, align 4
  %conn.addr = alloca %struct.connection*, align 8
  store i8* %ip, i8** %ip.addr, align 8
  store i32 %port, i32* %port.addr, align 4
  store %struct.connection* %conn, %struct.connection** %conn.addr, align 8
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable mustprogress
define dso_local i32 @send_msg(i8* %buff, i64 %buff_len, i64 %conn.coerce) #0 {
entry:
  %conn = alloca %struct.connection, align 4
  %buff.addr = alloca i8*, align 8
  %buff_len.addr = alloca i64, align 8
  %0 = bitcast %struct.connection* %conn to i64*
  store i64 %conn.coerce, i64* %0, align 4
  store i8* %buff, i8** %buff.addr, align 8
  store i64 %buff_len, i64* %buff_len.addr, align 8
  ret i32 0
}

; Function Attrs: noinline nounwind optnone uwtable mustprogress
define dso_local i32 @receive_msg(i8* %buff, i64 %buff_len, i64 %conn.coerce) #0 {
entry:
  %conn = alloca %struct.connection, align 4
  %buff.addr = alloca i8*, align 8
  %buff_len.addr = alloca i64, align 8
  %0 = bitcast %struct.connection* %conn to i64*
  store i64 %conn.coerce, i64* %0, align 4
  store i8* %buff, i8** %buff.addr, align 8
  store i64 %buff_len, i64* %buff_len.addr, align 8
  ret i32 0
}

; Function Attrs: noinline nounwind optnone uwtable mustprogress
define dso_local void @close(%struct.connection* %conn) #0 {
entry:
  %conn.addr = alloca %struct.connection*, align 8
  store %struct.connection* %conn, %struct.connection** %conn.addr, align 8
  ret void
}

attributes #0 = { noinline nounwind optnone uwtable mustprogress "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 12.0.0 (git@github.com:HexHive/libfuzz.git ff72fdb5c414c95581c37f9e0be2e28c2c8cc117)"}
