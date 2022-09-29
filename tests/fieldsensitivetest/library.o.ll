; ModuleID = 'library.o.bc'
source_filename = "llvm-link"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.my_struct = type { i32, i32, i32, i32 }

; Function Attrs: mustprogress nofree norecurse nosync nounwind uwtable willreturn
define dso_local void @swap_fields(%struct.my_struct* nocapture %0) local_unnamed_addr #0 {
  %2 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %0, i64 0, i32 0
  %3 = load i32, i32* %2, align 4, !tbaa !3
  %4 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %0, i64 0, i32 1
  %5 = load i32, i32* %4, align 4, !tbaa !8
  store i32 %5, i32* %2, align 4, !tbaa !3
  store i32 %3, i32* %4, align 4, !tbaa !8
  ret void
}

; Function Attrs: mustprogress nofree norecurse nosync nounwind uwtable willreturn
define dso_local void @my_api(%struct.my_struct* nocapture %0) local_unnamed_addr #0 {
  %2 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %0, i64 0, i32 0
  %3 = load i32, i32* %2, align 4, !tbaa !3
  %4 = icmp eq i32 %3, 0
  br i1 %4, label %5, label %8

5:                                                ; preds = %1
  %6 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %0, i64 0, i32 1
  %7 = load i32, i32* %6, align 4, !tbaa !8
  store i32 %7, i32* %2, align 4, !tbaa !3
  store i32 %3, i32* %6, align 4, !tbaa !8
  br label %8

8:                                                ; preds = %5, %1
  ret void
}

attributes #0 = { mustprogress nofree norecurse nosync nounwind uwtable willreturn "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.ident = !{!0}
!llvm.module.flags = !{!1, !2}

!0 = !{!"Ubuntu clang version 13.0.1-++20220120110924+75e33f71c2da-1~exp1~20220120231001.58"}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 7, !"uwtable", i32 1}
!3 = !{!4, !5, i64 0}
!4 = !{!"my_struct", !5, i64 0, !5, i64 4, !5, i64 8, !5, i64 12}
!5 = !{!"int", !6, i64 0}
!6 = !{!"omnipotent char", !7, i64 0}
!7 = !{!"Simple C/C++ TBAA"}
!8 = !{!4, !5, i64 4}
