/****************************************************************************
** Meta object code from reading C++ file 'opensf.h'
**
** Created: Tue Apr 23 18:57:58 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../opensf.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'opensf.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_OpenSF[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      16,    8,    7,    7, 0x0a,
      29,    7,    7,    7, 0x08,
      41,    7,    7,    7, 0x08,
      56,   52,    7,    7, 0x08,
      70,    7,    7,    7, 0x08,
      85,    7,    7,    7, 0x08,
     100,    7,    7,    7, 0x08,

       0        // eod
};

static const char qt_meta_stringdata_OpenSF[] = {
    "OpenSF\0\0pkt_num\0display(int)\0start_cap()\0"
    "stop_cap()\0row\0show_pkt(int)\0"
    "check_filter()\0apply_filter()\0"
    "clear_filter()\0"
};

void OpenSF::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        OpenSF *_t = static_cast<OpenSF *>(_o);
        switch (_id) {
        case 0: _t->display((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->start_cap(); break;
        case 2: _t->stop_cap(); break;
        case 3: _t->show_pkt((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->check_filter(); break;
        case 5: _t->apply_filter(); break;
        case 6: _t->clear_filter(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData OpenSF::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject OpenSF::staticMetaObject = {
    { &QMainWindow::staticMetaObject, qt_meta_stringdata_OpenSF,
      qt_meta_data_OpenSF, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &OpenSF::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *OpenSF::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *OpenSF::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_OpenSF))
        return static_cast<void*>(const_cast< OpenSF*>(this));
    return QMainWindow::qt_metacast(_clname);
}

int OpenSF::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
