; ModuleID = 'network_lib.cpp'
source_filename = "network_lib.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.connection = type { [4 x i8], i32, i32, i8 }

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @connect(i8* %0, i32 %1, %struct.connection* %2) #0 {
  %4 = alloca i8*, align 8
  %5 = alloca i32, align 4
  %6 = alloca %struct.connection*, align 8
  store i8* %0, i8** %4, align 8
  store i32 %1, i32* %5, align 4
  store %struct.connection* %2, %struct.connection** %6, align 8
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @send_msg(i8* %0, i64 %1, i64 %2, i64 %3) #0 {
  %5 = alloca %struct.connection, align 4
  %6 = alloca i8*, align 8
  %7 = alloca i64, align 8
  %8 = bitcast %struct.connection* %5 to { i64, i64 }*
  %9 = getelementptr inbounds { i64, i64 }, { i64, i64 }* %8, i32 0, i32 0
  store i64 %2, i64* %9, align 4
  %10 = getelementptr inbounds { i64, i64 }, { i64, i64 }* %8, i32 0, i32 1
  store i64 %3, i64* %10, align 4
  store i8* %0, i8** %6, align 8
  store i64 %1, i64* %7, align 8
  ret i32 0
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @receive_msg(i8* %0, i64 %1, i64 %2, i64 %3) #0 {
  %5 = alloca %struct.connection, align 4
  %6 = alloca i8*, align 8
  %7 = alloca i64, align 8
  %8 = bitcast %struct.connection* %5 to { i64, i64 }*
  %9 = getelementptr inbounds { i64, i64 }, { i64, i64 }* %8, i32 0, i32 0
  store i64 %2, i64* %9, align 4
  %10 = getelementptr inbounds { i64, i64 }, { i64, i64 }* %8, i32 0, i32 1
  store i64 %3, i64* %10, align 4
  store i8* %0, i8** %6, align 8
  store i64 %1, i64* %7, align 8
  ret i32 0
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @close(%struct.connection* %0) #0 {
  %2 = alloca %struct.connection*, align 8
  store %struct.connection* %0, %struct.connection** %2, align 8
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @_Z5PAPPA10connectioniS_(i64 %0, i64 %1, i32 %2, i64 %3, i64 %4) #0 {
  %6 = alloca %struct.connection, align 4
  %7 = alloca %struct.connection, align 4
  %8 = alloca i32, align 4
  %9 = bitcast %struct.connection* %6 to { i64, i64 }*
  %10 = getelementptr inbounds { i64, i64 }, { i64, i64 }* %9, i32 0, i32 0
  store i64 %0, i64* %10, align 4
  %11 = getelementptr inbounds { i64, i64 }, { i64, i64 }* %9, i32 0, i32 1
  store i64 %1, i64* %11, align 4
  %12 = bitcast %struct.connection* %7 to { i64, i64 }*
  %13 = getelementptr inbounds { i64, i64 }, { i64, i64 }* %12, i32 0, i32 0
  store i64 %3, i64* %13, align 4
  %14 = getelementptr inbounds { i64, i64 }, { i64, i64 }* %12, i32 0, i32 1
  store i64 %4, i64* %14, align 4
  store i32 %2, i32* %8, align 4
  ret void
}

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.0-4ubuntu1 "}
