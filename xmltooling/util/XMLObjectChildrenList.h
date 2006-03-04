/*
 *  Copyright 2001-2006 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file XMLObjectChildrenList.h
 * 
 * STL-compatible container wrapper
 */

#if !defined(__xmltooling_list_h__)
#define __xmltooling_list_h__

#include <xmltooling/DOMCachingXMLObject.h>
#include <xmltooling/exceptions.h>

#define ListOf(type) xmltooling::XMLObjectChildrenList<type>

namespace xmltooling {

    // Forward reference
    template <class _Tx, class _Ty=XMLObject> class XMLObjectChildrenList;

    /**
     * STL iterator that mediates access to an iterator over typed XML children.
     * @param _Ty   a bidrectional sequence of the subtype to iterate over
     */
    template <class _Ty>
    class XMLObjectChildrenIterator
    {
        typename _Ty::iterator m_iter;
        template <class _Tx, class _Tz> friend class XMLObjectChildrenList;
    public:
        typedef typename _Ty::iterator::iterator_category iterator_category;
        typedef typename _Ty::iterator::value_type value_type;
        typedef typename _Ty::iterator::reference reference;
        typedef typename _Ty::iterator::pointer pointer;
        typedef typename _Ty::const_iterator::reference const_reference;
        typedef typename _Ty::const_iterator::pointer const_pointer;
        typedef typename _Ty::iterator::difference_type difference_type;

        XMLObjectChildrenIterator() {
        }

        XMLObjectChildrenIterator(typename _Ty::iterator iter) {
            m_iter=iter;
        }

        const_reference operator*() const {
            return *m_iter;
        }

        pointer operator->() const {
            return (&**this);
        }

        XMLObjectChildrenIterator& operator++() {
            // preincrement
            ++m_iter;
            return (*this);
        }

        XMLObjectChildrenIterator& operator--() {
            // predecrement
            --m_iter;
            return (*this);
        }

        XMLObjectChildrenIterator operator++(int) {
            // postincrement
            XMLObjectChildrenIterator _Tmp = *this;
            ++*this;
            return (_Tmp);
        }

        XMLObjectChildrenIterator operator--(int) {
            // postdecrement
            XMLObjectChildrenIterator _Tmp = *this;
            --*this;
            return (_Tmp);
        }

        XMLObjectChildrenIterator& operator+=(difference_type _Off) {
            // increment by integer
            m_iter += _Off;
            return (*this);
        }

        XMLObjectChildrenIterator operator+(difference_type _Off) const {
            // return this + integer
            XMLObjectChildrenIterator _Tmp = *this;
            return (_Tmp += _Off);
        }

        XMLObjectChildrenIterator& operator-=(difference_type _Off) {
            // decrement by integer
            return (*this += -_Off);
        }

        XMLObjectChildrenIterator operator-(difference_type _Off) const {
            // return this - integer
            XMLObjectChildrenIterator _Tmp = *this;
            return (_Tmp -= _Off);
        }

        difference_type operator-(const XMLObjectChildrenIterator& _Right) const {
            // return difference of iterators
            return m_iter - _Right.m_iter;
        }

        const_reference operator[](difference_type _Off) const {
            // subscript
            return (*(*this + _Off));
        }

        bool operator==(const XMLObjectChildrenIterator &_Right) const {
		    // test for iterator equality
		    return (m_iter == _Right.m_iter);
	    }

	    bool operator!=(const XMLObjectChildrenIterator &_Right) const {
		    // test for iterator inequality
		    return (!(m_iter == _Right.m_iter));
	    }
    };

    /**
     * STL-compatible container that mediates access to underlying lists of typed XML children.
     * @param _Tx   the subtype to expose a container over
     * @param _Ty   the base type in the underlying list (defaults to XMLObject)
     */
    template <class _Tx, class _Ty>
    class XMLObjectChildrenList
    {
        typedef typename std::vector<_Tx*> container;
        typename XMLObjectChildrenList::container& m_vector;
        typename std::list<_Ty*>& m_list;
        typename std::list<_Ty*>::iterator m_fence;
        XMLObject* m_parent;

	public:
        typedef typename container::value_type value_type;
        typedef typename container::reference reference;
        typedef typename container::const_reference const_reference;
        typedef typename container::difference_type difference_type;
        typedef typename container::size_type size_type;

        // We override the iterator types with our constrained wrapper.
        typedef XMLObjectChildrenIterator<typename XMLObjectChildrenList::container> iterator;
        typedef const XMLObjectChildrenIterator<typename XMLObjectChildrenList::container> const_iterator;

        /**
         * Constructor to expose a typed collection of children backed by a list of a base type.
         *
         * @param parent    parent object of the collection
         * @param v         underlying vector of iterators that reference the children
         * @param backing   backing list for children
         * @param ins_fence a marker designating where new children of this type should be added
         */
        XMLObjectChildrenList(
            XMLObject* parent,
            typename XMLObjectChildrenList::container& v,
            typename std::list<_Ty*>& backing,
            typename std::list<_Ty*>::iterator ins_fence
            ) : m_parent(parent), m_vector(v), m_list(backing), m_fence(ins_fence) {
        }

        size_type size() const {
            // return length of sequence
            return m_vector.size();
        }

        bool empty() const {
            // test if sequence is empty
            return m_vector.empty();
        }

        iterator begin() {
            // return iterator for beginning of mutable sequence
            return m_vector.begin();
        }

        iterator end() {
            // return iterator for end of mutable sequence
            return m_vector.end();
        }

        const_iterator begin() const {
            // return iterator for beginning of const sequence
            return m_vector.begin();
        }

        const_iterator end() const {
            // return iterator for end of const sequence
            return m_vector.end();
        }

        const_reference at(size_type _Pos) const {
            // subscript nonmutable sequence with checking
            return m_vector.at(_Pos);
        }

        const_reference operator[](size_type _Pos) const {
            // subscript nonmutable sequence
            return m_vector[_Pos];
        }

        const_reference front() const {
            // return first element of nonmutable sequence
            return (*begin());
        }

        const_reference back() const {
            // return last element of nonmutable sequence
            return *(m_vector.back());
        }

        void push_back(const_reference _Val) {
            setParent(_Val);
            m_list.insert(m_fence,_Val);
            m_vector.push_back(_Val);
        }

        iterator erase(iterator _Where) {
            removeParent(*_Where);
            removeChild(*_Where);
            return m_vector.erase(_Where.m_iter);
        }

        iterator erase(iterator _First, iterator _Last) {
            for (iterator i=_First; i!=_Last; i++) {
                removeParent(*i);
                removeChild(*i);
            }
            return m_vector.erase(_First,_Last);
        }

    private:
        void setParent(const_reference _Val) {
            if (_Val->getParent())
                throw XMLObjectException("Child object already has a parent.");
            _Val->setParent(m_parent);
            DOMCachingXMLObject* dc=dynamic_cast<DOMCachingXMLObject*>(_Val);
            if (dc) {
                dc->releaseParentDOM(true);
            }
        }

        void removeParent(const_reference _Val) {
            if (_Val->getParent()!=m_parent)
                throw XMLObjectException("Child object not owned by this parent.");
            _Val->setParent(NULL);
            DOMCachingXMLObject* dc=dynamic_cast<DOMCachingXMLObject*>(m_parent);
            if (dc) {
                dc->releaseParentDOM(true);
            }
        }

        void removeChild(const_reference _Val) {
            for (typename std::list<_Ty*>::iterator i=m_list.begin(); i!=m_list.end(); i++) {
                if ((*i)==_Val) {
                    m_list.erase(i);
                    delete _Val;
                    return;
                }
            }
        }
    };

};

#endif /* __xmltooling_list_h__ */
