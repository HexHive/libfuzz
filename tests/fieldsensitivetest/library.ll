; ModuleID = 'library.c'
source_filename = "library.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.my_struct = type { i32, i32 }

; Function Attrs: noinline nounwind uwtable
define dso_local void @update_field(ptr noundef %m) #0 {
entry:
  %m.addr = alloca ptr, align 8
  store ptr %m, ptr %m.addr, align 8
  %0 = load ptr, ptr %m.addr, align 8
  %field_b = getelementptr inbounds %struct.my_struct, ptr %0, i32 0, i32 1
  store i32 5, ptr %field_b, align 4
  ret void
}

; Function Attrs: noinline nounwind uwtable
define dso_local void @swap_fields(ptr noundef %m) #0 {
entry:
  %m.addr = alloca ptr, align 8
  %t = alloca i32, align 4
  store ptr %m, ptr %m.addr, align 8
  %0 = load ptr, ptr %m.addr, align 8
  %field_a = getelementptr inbounds %struct.my_struct, ptr %0, i32 0, i32 0
  %1 = load i32, ptr %field_a, align 4
  store i32 %1, ptr %t, align 4
  %2 = load ptr, ptr %m.addr, align 8
  %field_b = getelementptr inbounds %struct.my_struct, ptr %2, i32 0, i32 1
  %3 = load i32, ptr %field_b, align 4
  %4 = load ptr, ptr %m.addr, align 8
  %field_a1 = getelementptr inbounds %struct.my_struct, ptr %4, i32 0, i32 0
  store i32 %3, ptr %field_a1, align 4
  %5 = load i32, ptr %t, align 4
  %6 = load ptr, ptr %m.addr, align 8
  %field_b2 = getelementptr inbounds %struct.my_struct, ptr %6, i32 0, i32 1
  store i32 %5, ptr %field_b2, align 4
  ret void
}

; Function Attrs: noinline nounwind uwtable
define dso_local void @my_api(ptr noundef %m) #0 {
entry:
  %m.addr = alloca ptr, align 8
  store ptr %m, ptr %m.addr, align 8
  %0 = load ptr, ptr %m.addr, align 8
  %field_a = getelementptr inbounds %struct.my_struct, ptr %0, i32 0, i32 0
  %1 = load i32, ptr %field_a, align 4
  %cmp = icmp eq i32 %1, 0
  br i1 %cmp, label %if.then, label %if.else

if.then:                                          ; preds = %entry
  %2 = load ptr, ptr %m.addr, align 8
  call void @update_field(ptr noundef %2)
  br label %if.end

if.else:                                          ; preds = %entry
  %3 = load ptr, ptr %m.addr, align 8
  call void @swap_fields(ptr noundef %3)
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  ret void
}

attributes #0 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 15.0.0-++20220725052911+3bbd380a5b51-1~exp1~20220725173012.325"}
