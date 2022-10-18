; ModuleID = 'library.o.bc'
source_filename = "llvm-link"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.tiff = type { i8*, i32, i32, i32, i64*, i16, %struct.client_info*, i64 }
%struct.client_info = type { %struct.client_info*, i8*, i8* }

; Function Attrs: mustprogress nofree norecurse nosync nounwind readnone uwtable willreturn
define dso_local void @TIFFFlush(%struct.tiff* nocapture %0) local_unnamed_addr #0 !dbg !8 {
  call void @llvm.dbg.value(metadata %struct.tiff* undef, metadata !51, metadata !DIExpression()), !dbg !52
  call void @llvm.dbg.value(metadata %struct.tiff* null, metadata !51, metadata !DIExpression()), !dbg !52
  ret void, !dbg !53
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #1

; Function Attrs: mustprogress nofree norecurse nosync nounwind readnone uwtable willreturn
define dso_local void @TIFFFreeDirectory(%struct.tiff* nocapture %0) local_unnamed_addr #0 !dbg !54 {
  call void @llvm.dbg.value(metadata %struct.tiff* undef, metadata !56, metadata !DIExpression()), !dbg !57
  call void @llvm.dbg.value(metadata %struct.tiff* null, metadata !56, metadata !DIExpression()), !dbg !57
  ret void, !dbg !58
}

; Function Attrs: mustprogress nounwind uwtable willreturn
define dso_local void @_TIFFfree(i8* nocapture %0) local_unnamed_addr #2 !dbg !59 {
  call void @llvm.dbg.value(metadata i8* %0, metadata !63, metadata !DIExpression()), !dbg !64
  tail call void @free(i8* %0) #5, !dbg !65
  ret void, !dbg !66
}

; Function Attrs: inaccessiblemem_or_argmemonly mustprogress nounwind willreturn
declare dso_local void @free(i8* nocapture noundef) local_unnamed_addr #3

; Function Attrs: nounwind uwtable
define dso_local void @api1(%struct.tiff* nocapture %0) local_unnamed_addr #4 !dbg !67 {
  call void @llvm.dbg.value(metadata %struct.tiff* %0, metadata !69, metadata !DIExpression()), !dbg !72
  %2 = getelementptr inbounds %struct.tiff, %struct.tiff* %0, i64 0, i32 4, !dbg !73
  %3 = load i64*, i64** %2, align 8, !dbg !73, !tbaa !75
  %4 = icmp eq i64* %3, null, !dbg !83
  br i1 %4, label %7, label %5, !dbg !84

5:                                                ; preds = %1
  %6 = bitcast i64* %3 to i8*, !dbg !85
  call void @llvm.dbg.value(metadata i8* %6, metadata !63, metadata !DIExpression()) #5, !dbg !86
  tail call void @free(i8* %6) #5, !dbg !88
  br label %7, !dbg !89

7:                                                ; preds = %5, %1
  %8 = getelementptr inbounds %struct.tiff, %struct.tiff* %0, i64 0, i32 6
  %9 = load %struct.client_info*, %struct.client_info** %8, align 8, !dbg !90, !tbaa !91
  %10 = icmp eq %struct.client_info* %9, null, !dbg !92
  br i1 %10, label %20, label %11, !dbg !92

11:                                               ; preds = %7, %11
  %12 = phi %struct.client_info* [ %18, %11 ], [ %9, %7 ]
  call void @llvm.dbg.value(metadata %struct.client_info* %12, metadata !70, metadata !DIExpression()), !dbg !93
  %13 = getelementptr inbounds %struct.client_info, %struct.client_info* %12, i64 0, i32 0, !dbg !94
  %14 = load %struct.client_info*, %struct.client_info** %13, align 8, !dbg !94, !tbaa !95
  store %struct.client_info* %14, %struct.client_info** %8, align 8, !dbg !97, !tbaa !91
  %15 = getelementptr inbounds %struct.client_info, %struct.client_info* %12, i64 0, i32 2, !dbg !98
  %16 = load i8*, i8** %15, align 8, !dbg !98, !tbaa !99
  call void @llvm.dbg.value(metadata i8* %16, metadata !63, metadata !DIExpression()) #5, !dbg !100
  tail call void @free(i8* %16) #5, !dbg !102
  %17 = bitcast %struct.client_info* %12 to i8*, !dbg !103
  call void @llvm.dbg.value(metadata i8* %17, metadata !63, metadata !DIExpression()) #5, !dbg !104
  tail call void @free(i8* %17) #5, !dbg !106
  %18 = load %struct.client_info*, %struct.client_info** %8, align 8, !dbg !90, !tbaa !91
  %19 = icmp eq %struct.client_info* %18, null, !dbg !92
  br i1 %19, label %20, label %11, !dbg !92, !llvm.loop !107

20:                                               ; preds = %11, %7
  ret void, !dbg !110
}

attributes #0 = { mustprogress nofree norecurse nosync nounwind readnone uwtable willreturn "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { mustprogress nounwind uwtable willreturn "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { inaccessiblemem_or_argmemonly mustprogress nounwind willreturn "frame-pointer"="none" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nounwind uwtable "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.ident = !{!3}
!llvm.module.flags = !{!4, !5, !6, !7}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 13.0.0", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !2, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "library.c", directory: "/workspaces/libfuzz/regression_tests/condition_extractor/linkedlist")
!2 = !{}
!3 = !{!"clang version 13.0.0"}
!4 = !{i32 7, !"Dwarf Version", i32 4}
!5 = !{i32 2, !"Debug Info Version", i32 3}
!6 = !{i32 1, !"wchar_size", i32 4}
!7 = !{i32 7, !"uwtable", i32 1}
!8 = distinct !DISubprogram(name: "TIFFFlush", scope: !1, file: !1, line: 9, type: !9, scopeLine: 9, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !50)
!9 = !DISubroutineType(types: !10)
!10 = !{null, !11}
!11 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_typedef, name: "TIFF", file: !13, line: 32, baseType: !14)
!13 = !DIFile(filename: "./library.h", directory: "/workspaces/libfuzz/regression_tests/condition_extractor/linkedlist")
!14 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "tiff", file: !13, line: 22, size: 448, elements: !15)
!15 = !{!16, !19, !21, !22, !28, !33, !37, !47}
!16 = !DIDerivedType(tag: DW_TAG_member, name: "tif_name", scope: !14, file: !13, line: 23, baseType: !17, size: 64)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!18 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "tif_fd", scope: !14, file: !13, line: 24, baseType: !20, size: 32, offset: 64)
!20 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "tif_mode", scope: !14, file: !13, line: 25, baseType: !20, size: 32, offset: 96)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "tif_flags", scope: !14, file: !13, line: 26, baseType: !23, size: 32, offset: 128)
!23 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint32_t", file: !24, line: 26, baseType: !25)
!24 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/stdint-uintn.h", directory: "")
!25 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint32_t", file: !26, line: 42, baseType: !27)
!26 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types.h", directory: "")
!27 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!28 = !DIDerivedType(tag: DW_TAG_member, name: "tif_dirlist", scope: !14, file: !13, line: 27, baseType: !29, size: 64, offset: 192)
!29 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !30, size: 64)
!30 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint64_t", file: !24, line: 27, baseType: !31)
!31 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint64_t", file: !26, line: 45, baseType: !32)
!32 = !DIBasicType(name: "long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "tif_dirlistsize", scope: !14, file: !13, line: 28, baseType: !34, size: 16, offset: 256)
!34 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint16_t", file: !24, line: 25, baseType: !35)
!35 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint16_t", file: !26, line: 40, baseType: !36)
!36 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!37 = !DIDerivedType(tag: DW_TAG_member, name: "tif_clientinfo", scope: !14, file: !13, line: 28, baseType: !38, size: 64, offset: 320)
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_typedef, name: "TIFFClientInfoLink", file: !13, line: 20, baseType: !40)
!40 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "client_info", file: !13, line: 16, size: 192, elements: !41)
!41 = !{!42, !44, !46}
!42 = !DIDerivedType(tag: DW_TAG_member, name: "next", scope: !40, file: !13, line: 17, baseType: !43, size: 64)
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !40, file: !13, line: 18, baseType: !45, size: 64, offset: 64)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!46 = !DIDerivedType(tag: DW_TAG_member, name: "name", scope: !40, file: !13, line: 19, baseType: !17, size: 64, offset: 128)
!47 = !DIDerivedType(tag: DW_TAG_member, name: "tif_nfieldscompat", scope: !14, file: !13, line: 31, baseType: !48, size: 64, offset: 384)
!48 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_t", file: !49, line: 46, baseType: !32)
!49 = !DIFile(filename: "/root/SVF/llvm-13.0.0.obj/lib/clang/13.0.0/include/stddef.h", directory: "")
!50 = !{!51}
!51 = !DILocalVariable(name: "tif", arg: 1, scope: !8, file: !1, line: 9, type: !11)
!52 = !DILocation(line: 0, scope: !8)
!53 = !DILocation(line: 11, column: 1, scope: !8)
!54 = distinct !DISubprogram(name: "TIFFFreeDirectory", scope: !1, file: !1, line: 13, type: !9, scopeLine: 13, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !55)
!55 = !{!56}
!56 = !DILocalVariable(name: "tif", arg: 1, scope: !54, file: !1, line: 13, type: !11)
!57 = !DILocation(line: 0, scope: !54)
!58 = !DILocation(line: 15, column: 1, scope: !54)
!59 = distinct !DISubprogram(name: "_TIFFfree", scope: !1, file: !1, line: 17, type: !60, scopeLine: 17, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !62)
!60 = !DISubroutineType(types: !61)
!61 = !{null, !45}
!62 = !{!63}
!63 = !DILocalVariable(name: "p", arg: 1, scope: !59, file: !1, line: 17, type: !45)
!64 = !DILocation(line: 0, scope: !59)
!65 = !DILocation(line: 18, column: 4, scope: !59)
!66 = !DILocation(line: 19, column: 1, scope: !59)
!67 = distinct !DISubprogram(name: "api1", scope: !1, file: !1, line: 23, type: !9, scopeLine: 24, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !68)
!68 = !{!69, !70}
!69 = !DILocalVariable(name: "tif", arg: 1, scope: !67, file: !1, line: 23, type: !11)
!70 = !DILocalVariable(name: "psLink", scope: !71, file: !1, line: 41, type: !38)
!71 = distinct !DILexicalBlock(scope: !67, file: !1, line: 40, column: 2)
!72 = !DILocation(line: 0, scope: !67)
!73 = !DILocation(line: 33, column: 11, scope: !74)
!74 = distinct !DILexicalBlock(scope: !67, file: !1, line: 33, column: 6)
!75 = !{!76, !77, i64 24}
!76 = !{!"tiff", !77, i64 0, !80, i64 8, !80, i64 12, !80, i64 16, !77, i64 24, !81, i64 32, !77, i64 40, !82, i64 48}
!77 = !{!"any pointer", !78, i64 0}
!78 = !{!"omnipotent char", !79, i64 0}
!79 = !{!"Simple C/C++ TBAA"}
!80 = !{!"int", !78, i64 0}
!81 = !{!"short", !78, i64 0}
!82 = !{!"long", !78, i64 0}
!83 = !DILocation(line: 33, column: 6, scope: !74)
!84 = !DILocation(line: 33, column: 6, scope: !67)
!85 = !DILocation(line: 34, column: 13, scope: !74)
!86 = !DILocation(line: 0, scope: !59, inlinedAt: !87)
!87 = distinct !DILocation(line: 34, column: 3, scope: !74)
!88 = !DILocation(line: 18, column: 4, scope: !59, inlinedAt: !87)
!89 = !DILocation(line: 34, column: 3, scope: !74)
!90 = !DILocation(line: 39, column: 14, scope: !67)
!91 = !{!76, !77, i64 40}
!92 = !DILocation(line: 39, column: 2, scope: !67)
!93 = !DILocation(line: 0, scope: !71)
!94 = !DILocation(line: 43, column: 33, scope: !71)
!95 = !{!96, !77, i64 0}
!96 = !{!"client_info", !77, i64 0, !77, i64 8, !77, i64 16}
!97 = !DILocation(line: 43, column: 23, scope: !71)
!98 = !DILocation(line: 44, column: 22, scope: !71)
!99 = !{!96, !77, i64 16}
!100 = !DILocation(line: 0, scope: !59, inlinedAt: !101)
!101 = distinct !DILocation(line: 44, column: 3, scope: !71)
!102 = !DILocation(line: 18, column: 4, scope: !59, inlinedAt: !101)
!103 = !DILocation(line: 45, column: 14, scope: !71)
!104 = !DILocation(line: 0, scope: !59, inlinedAt: !105)
!105 = distinct !DILocation(line: 45, column: 3, scope: !71)
!106 = !DILocation(line: 18, column: 4, scope: !59, inlinedAt: !105)
!107 = distinct !{!107, !92, !108, !109}
!108 = !DILocation(line: 46, column: 2, scope: !67)
!109 = !{!"llvm.loop.mustprogress"}
!110 = !DILocation(line: 47, column: 1, scope: !67)
